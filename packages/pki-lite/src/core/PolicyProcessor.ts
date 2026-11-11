import { Certificate } from '../x509/Certificate.js'
import { CertificatePolicies } from '../x509/extensions/CertificatePolicies.js'
import { InhibitAnyPolicy } from '../x509/extensions/InhibitAnyPolicy.js'
import { PolicyConstraints } from '../x509/extensions/PolicyConstraints.js'
import { PolicyMappings } from '../x509/extensions/PolicyMappings.js'
import { OIDs } from './OIDs.js'

/** The special `anyPolicy` identifier */
export const ANY_POLICY = OIDs.EXTENSION.ANY_POLICY

/** Inputs of the RFC 5280 6.1.1 certificate policy processing */
export interface PolicyProcessingOptions {
    /** user-initial-policy-set: acceptable policies (default: any policy) */
    initialPolicySet?: string[]
    /** initial-explicit-policy: an acceptable policy is required in every case */
    initialExplicitPolicy?: boolean
    /** initial-policy-mapping-inhibit: policy mapping is not allowed */
    initialPolicyMappingInhibit?: boolean
    /** initial-any-policy-inhibit: anyPolicy is not considered a match */
    initialAnyPolicyInhibit?: boolean
}

export interface PolicyProcessingResult {
    /** whether path processing succeeded (RFC 5280 6.1.5 (g)) */
    isValid: boolean
    /** the user-constrained policy set: the policies valid for the whole path */
    validPolicies: string[]
    /** why processing failed */
    violations: string[]
}

interface PolicyNode {
    policy: string
    expected: Set<string>
    parent?: PolicyNode
    children: PolicyNode[]
}

class PolicyTree {
    /** levels[d] are the nodes of depth d; the root is anyPolicy at depth 0 */
    levels: PolicyNode[][]

    constructor() {
        this.levels = [
            [
                {
                    policy: ANY_POLICY,
                    expected: new Set([ANY_POLICY]),
                    children: [],
                },
            ],
        ]
    }

    /** makes this the NULL tree of RFC 5280 */
    nullify() {
        this.levels = [[]]
    }

    get isNull() {
        return this.levels[0].length === 0
    }

    addChild(parent: PolicyNode, depth: number, policy: string): PolicyNode {
        const child: PolicyNode = {
            policy,
            expected: new Set([policy]),
            parent,
            children: [],
        }
        parent.children.push(child)
        ;(this.levels[depth] ??= []).push(child)
        return child
    }

    /** deletes a node and its descendants */
    remove(depth: number, node: PolicyNode) {
        this.levels[depth] = this.levels[depth].filter((n) => n !== node)
        node.parent?.children.splice(node.parent.children.indexOf(node), 1)
        for (const child of [...node.children]) this.remove(depth + 1, child)
    }

    /** deletes nodes above `depth` (inclusive) without children, bottom-up */
    prune(depth: number) {
        for (let d = depth; d >= 0; d--) {
            for (const node of [...this.levels[d]]) {
                if (node.children.length === 0) this.remove(d, node)
            }
        }
    }
}

/**
 * Certificate policy processing of RFC 5280 6.1 (the valid_policy_tree, the explicit_policy,
 * policy_mapping and inhibit_anyPolicy counters).
 *
 * @param path the certification path from the leaf to the CA below the trust anchor (the
 *   trust anchor itself is not part of it)
 * @param isSelfIssued whether a certificate's issuer and subject are the same
 */
export function processPolicies(
    path: Certificate[],
    isSelfIssued: (certificate: Certificate) => boolean,
    options: PolicyProcessingOptions = {},
): PolicyProcessingResult {
    const certificates = [...path].reverse() // the CA nearest the trust anchor first
    const n = certificates.length
    const fail = (violation: string): PolicyProcessingResult => ({
        isValid: false,
        validPolicies: [],
        violations: [violation],
    })

    const tree = new PolicyTree()
    let explicitPolicy = options.initialExplicitPolicy ? 0 : n + 1
    let policyMapping = options.initialPolicyMappingInhibit ? 0 : n + 1
    let inhibitAnyPolicy = options.initialAnyPolicyInhibit ? 0 : n + 1

    const read = <T>(
        certificate: Certificate,
        oid: string,
        cls: { fromAsn1: unknown } & (new (...args: never[]) => T),
    ): T | undefined | Error => {
        const extension = certificate.getExtensionByOid(oid)
        if (!extension) return undefined
        try {
            return extension.extnValue.parseAs(cls as never) as T
        } catch (error) {
            return error instanceof Error ? error : new Error(String(error))
        }
    }
    const describe = (certificate: Certificate) =>
        `'${certificate.tbsCertificate.subject.toHumanString()}'`

    for (let i = 1; i <= n; i++) {
        const certificate = certificates[i - 1]
        const last = i === n
        const selfIssued = isSelfIssued(certificate)

        const policies = read(
            certificate,
            OIDs.EXTENSION.CERTIFICATE_POLICIES,
            CertificatePolicies as never,
        ) as CertificatePolicies | undefined | Error
        if (policies instanceof Error) {
            return fail(
                `cannot read the certificate policies of ${describe(certificate)}: ${policies.message}`,
            )
        }

        // 6.1.3 (d)/(e)
        if (policies && !tree.isNull) {
            tree.levels[i] = []
            const parents = tree.levels[i - 1]
            let anyPolicyInCert = false
            for (const information of policies) {
                const policy = information.policyIdentifier.value
                if (policy === ANY_POLICY) {
                    anyPolicyInCert = true
                    continue
                }
                let matched = false
                for (const parent of parents) {
                    if (parent.expected.has(policy)) {
                        tree.addChild(parent, i, policy)
                        matched = true
                    }
                }
                if (!matched) {
                    for (const parent of parents) {
                        if (parent.policy === ANY_POLICY) {
                            tree.addChild(parent, i, policy)
                        }
                    }
                }
            }
            if (
                anyPolicyInCert &&
                (inhibitAnyPolicy > 0 || (selfIssued && !last))
            ) {
                for (const parent of parents) {
                    for (const expected of parent.expected) {
                        if (
                            !parent.children.some((c) => c.policy === expected)
                        ) {
                            tree.addChild(parent, i, expected)
                        }
                    }
                }
            }
            tree.prune(i - 1)
            if (tree.isNull) tree.nullify()
        } else if (!policies) {
            tree.nullify()
        }

        // 6.1.3 (f)
        if (!(explicitPolicy > 0 || !tree.isNull)) {
            return fail(
                `no acceptable policy: ${describe(certificate)} leaves no valid policy and a policy is required`,
            )
        }

        const constraints = read(
            certificate,
            OIDs.EXTENSION.POLICY_CONSTRAINTS,
            PolicyConstraints as never,
        ) as PolicyConstraints | undefined | Error
        if (constraints instanceof Error) {
            return fail(
                `cannot read the policy constraints of ${describe(certificate)}: ${constraints.message}`,
            )
        }

        if (last) {
            // 6.1.5 (a)/(b)
            if (explicitPolicy > 0) explicitPolicy--
            if (constraints?.requireExplicitPolicy === 0) explicitPolicy = 0
            break
        }

        // 6.1.4 (a)/(b): policy mappings
        const mappings = read(
            certificate,
            OIDs.EXTENSION.POLICY_MAPPINGS,
            PolicyMappings as never,
        ) as PolicyMappings | undefined | Error
        if (mappings instanceof Error) {
            return fail(
                `cannot read the policy mappings of ${describe(certificate)}: ${mappings.message}`,
            )
        }
        if (mappings && !tree.isNull) {
            const byIssuer = new Map<string, Set<string>>()
            for (const mapping of mappings) {
                const issuer = mapping.issuerDomainPolicy.value
                const subject = mapping.subjectDomainPolicy.value
                if (issuer === ANY_POLICY || subject === ANY_POLICY) {
                    return fail(
                        `${describe(certificate)} maps anyPolicy, which RFC 5280 4.2.1.5 forbids`,
                    )
                }
                if (!byIssuer.has(issuer)) byIssuer.set(issuer, new Set())
                byIssuer.get(issuer)!.add(subject)
            }
            for (const [issuer, subjects] of byIssuer) {
                const nodes = tree.levels[i].filter(
                    (node) => node.policy === issuer,
                )
                if (policyMapping > 0) {
                    if (nodes.length > 0) {
                        for (const node of nodes)
                            node.expected = new Set(subjects)
                    } else {
                        for (const parent of tree.levels[i - 1]) {
                            if (parent.policy === ANY_POLICY) {
                                tree.addChild(parent, i, issuer).expected =
                                    new Set(subjects)
                            }
                        }
                    }
                } else {
                    for (const node of nodes) tree.remove(i, node)
                    tree.prune(i - 1)
                }
            }
            if (tree.isNull) tree.nullify()
        }

        // 6.1.4 (h)-(j)
        if (!selfIssued) {
            if (explicitPolicy > 0) explicitPolicy--
            if (policyMapping > 0) policyMapping--
            if (inhibitAnyPolicy > 0) inhibitAnyPolicy--
        }
        if (constraints) {
            if (constraints.requireExplicitPolicy !== undefined) {
                explicitPolicy = Math.min(
                    explicitPolicy,
                    constraints.requireExplicitPolicy,
                )
            }
            if (constraints.inhibitPolicyMapping !== undefined) {
                policyMapping = Math.min(
                    policyMapping,
                    constraints.inhibitPolicyMapping,
                )
            }
        }
        const inhibit = read(
            certificate,
            OIDs.EXTENSION.INHIBIT_ANY_POLICY,
            InhibitAnyPolicy as never,
        ) as InhibitAnyPolicy | undefined | Error
        if (inhibit instanceof Error) {
            return fail(
                `cannot read the inhibit any policy extension of ${describe(certificate)}: ${inhibit.message}`,
            )
        }
        if (inhibit) {
            inhibitAnyPolicy = Math.min(inhibitAnyPolicy, inhibit.skipCerts)
        }
    }

    // 6.1.5 (g): intersect with the user-initial-policy-set
    const initial = options.initialPolicySet
    if (
        !tree.isNull &&
        initial &&
        initial.length > 0 &&
        !initial.includes(ANY_POLICY)
    ) {
        const set = new Set(initial)
        const nodeSet: [number, PolicyNode][] = []
        tree.levels.forEach((level, depth) =>
            level.forEach((node) => {
                if (node.parent?.policy === ANY_POLICY)
                    nodeSet.push([depth, node])
            }),
        )
        for (const [depth, node] of nodeSet) {
            if (node.policy !== ANY_POLICY && !set.has(node.policy)) {
                tree.remove(depth, node)
            }
        }
        const anyNode = (tree.levels[n] ?? []).find(
            (node) => node.policy === ANY_POLICY,
        )
        if (anyNode) {
            const present = new Set(
                nodeSet
                    .filter(([, node]) => node.policy !== ANY_POLICY)
                    .map(([, node]) => node.policy),
            )
            for (const policy of set) {
                if (!present.has(policy) && anyNode.parent) {
                    tree.addChild(anyNode.parent, n, policy)
                }
            }
            tree.remove(n, anyNode)
        }
        tree.prune(n - 1)
        if (tree.isNull) tree.nullify()
    }

    const validPolicies = tree.isNull
        ? []
        : [...new Set((tree.levels[n] ?? []).map((node) => node.policy))]

    if (explicitPolicy > 0 || !tree.isNull) {
        return { isValid: true, validPolicies, violations: [] }
    }
    return fail(
        'no acceptable certificate policy for the path (explicit policy is required)',
    )
}
