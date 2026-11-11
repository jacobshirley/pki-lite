/**
 * Certificate policy processing (RFC 5280 6.1) on real certificates: every chain here is
 * issued by the OpenSSL CLI with OpenSSL's own policy extensions, and each scenario is
 * checked against both pki-lite's validator and `openssl verify -policy_check`. The
 * expected verdicts are written out, so a disagreement shows which side is wrong.
 *
 * OpenSSL quirk: with `-explicit_policy` and no `-policy`, `openssl verify` fails every
 * path (its user policy set stays empty). RFC 5280's default user-initial-policy-set is
 * any-policy, so OpenSSL is always given `-policy` (anyPolicy when nothing narrower).
 */
import fs from 'fs'
import path from 'path'
import { randomUUID } from 'crypto'
import { beforeAll, describe, expect, test } from 'vitest'
import { runOpenSSL } from '../../test-fixtures/openSsl.js'
import { CertificateValidator } from '../../src/core/CertificateValidator.js'
import { Certificate } from '../../src/x509/Certificate.js'

const A = '1.2.3.4.1'
const B = '1.2.3.4.2'
const ANY = '2.5.29.32.0'

/** One CA below the root, described as OpenSSL extension config lines */
type CaSpec = {
    policies?: string[]
    mappings?: [string, string][]
    requireExplicitPolicy?: number
    inhibitPolicyMapping?: number
    inhibitAnyPolicy?: number
}

type Scenario = {
    name: string
    /** CAs from the one below the root down to the leaf's issuer */
    cas: CaSpec[]
    leafPolicies?: string[]
    /** user-initial-policy-set (default any-policy) */
    initialPolicySet?: string[]
    initialExplicitPolicy?: boolean
    initialPolicyMappingInhibit?: boolean
    initialAnyPolicyInhibit?: boolean
    valid: boolean
    /** the user-constrained policy set, when valid */
    validPolicies?: string[]
}

const scenarios: Scenario[] = [
    {
        name: 'no policies anywhere',
        cas: [{}],
        valid: true,
        validPolicies: [],
    },
    {
        name: 'no policies, explicit policy required',
        cas: [{}],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'the same policy all the way down',
        cas: [{ policies: [A] }],
        leafPolicies: [A],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [A],
    },
    {
        name: 'a leaf policy the CA never asserted',
        cas: [{ policies: [A] }],
        leafPolicies: [B],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'anyPolicy in the CA admits the leaf policy',
        cas: [{ policies: [ANY] }],
        leafPolicies: [B],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [B],
    },
    {
        name: 'anyPolicy in the leaf takes the CA policy',
        cas: [{ policies: [A] }],
        leafPolicies: [ANY],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [A],
    },
    {
        name: 'initial policy set narrows the result',
        cas: [{ policies: [A, B] }],
        leafPolicies: [A, B],
        initialPolicySet: [B],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [B],
    },
    {
        name: 'initial policy set with no match',
        cas: [{ policies: [A] }],
        leafPolicies: [A],
        initialPolicySet: [B],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'policy mapping: the leaf uses the mapped policy',
        cas: [{ policies: [A], mappings: [[A, B]] }],
        leafPolicies: [B],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [B],
    },
    {
        name: 'policy mapping: the issuer-domain policy is not valid below',
        cas: [{ policies: [A], mappings: [[A, B]] }],
        leafPolicies: [A],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'policy mapping: initial set in the issuer domain',
        cas: [{ policies: [A], mappings: [[A, B]] }],
        leafPolicies: [B],
        initialPolicySet: [A],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [B],
    },
    {
        name: 'policy mapping: initial set in the subject domain',
        cas: [{ policies: [A], mappings: [[A, B]] }],
        leafPolicies: [B],
        initialPolicySet: [B],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'policy mapping inhibited by the relying party',
        cas: [{ policies: [A], mappings: [[A, B]] }],
        leafPolicies: [B],
        initialExplicitPolicy: true,
        initialPolicyMappingInhibit: true,
        valid: false,
    },
    {
        name: 'requireExplicitPolicy in the CA, leaf without policies',
        cas: [{ requireExplicitPolicy: 0 }],
        valid: false,
    },
    {
        name: 'requireExplicitPolicy in the CA, policies present',
        cas: [{ policies: [A], requireExplicitPolicy: 0 }],
        leafPolicies: [A],
        valid: true,
        validPolicies: [A],
    },
    {
        name: 'requireExplicitPolicy: 1 skips one certificate',
        cas: [{ requireExplicitPolicy: 1 }, {}],
        valid: false,
    },
    {
        name: 'anyPolicy inhibited by the relying party',
        cas: [{ policies: [A] }],
        leafPolicies: [ANY],
        initialExplicitPolicy: true,
        initialAnyPolicyInhibit: true,
        valid: false,
    },
    {
        name: 'inhibitAnyPolicy: 0 stops anyPolicy in the next CA',
        cas: [{ policies: [ANY], inhibitAnyPolicy: 0 }, { policies: [ANY] }],
        leafPolicies: [A],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'inhibitAnyPolicy: 1 still allows the next CA',
        cas: [{ policies: [ANY], inhibitAnyPolicy: 1 }, { policies: [ANY] }],
        leafPolicies: [A],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [A],
    },
    {
        name: 'inhibitPolicyMapping: 0 stops the next CA mapping',
        cas: [
            { policies: [A], inhibitPolicyMapping: 0 },
            { policies: [A], mappings: [[A, B]] },
        ],
        leafPolicies: [B],
        initialExplicitPolicy: true,
        valid: false,
    },
    {
        name: 'inhibitPolicyMapping: 1 lets the next CA map',
        cas: [
            { policies: [A], inhibitPolicyMapping: 1 },
            { policies: [A], mappings: [[A, B]] },
        ],
        leafPolicies: [B],
        initialExplicitPolicy: true,
        valid: true,
        validPolicies: [B],
    },
]

function caConfig(ca: CaSpec): string {
    const lines = [
        'basicConstraints=critical,CA:TRUE',
        'keyUsage=critical,keyCertSign,cRLSign',
    ]
    if (ca.policies) lines.push(`certificatePolicies=${ca.policies.join(',')}`)
    if (ca.mappings) {
        lines.push(
            `policyMappings=${ca.mappings.map(([i, s]) => `${i}:${s}`).join(',')}`,
        )
    }
    const constraints = [
        ca.requireExplicitPolicy !== undefined &&
            `requireExplicitPolicy:${ca.requireExplicitPolicy}`,
        ca.inhibitPolicyMapping !== undefined &&
            `inhibitPolicyMapping:${ca.inhibitPolicyMapping}`,
    ].filter(Boolean)
    if (constraints.length) {
        lines.push(`policyConstraints=critical,${constraints.join(',')}`)
    }
    if (ca.inhibitAnyPolicy !== undefined) {
        lines.push(`inhibitAnyPolicy=critical,${ca.inhibitAnyPolicy}`)
    }
    return `[ext]\n${lines.join('\n')}\n`
}

function leafConfig(policies?: string[]): string {
    const lines = ['basicConstraints=CA:FALSE']
    if (policies) lines.push(`certificatePolicies=${policies.join(',')}`)
    return `[ext]\n${lines.join('\n')}\n`
}

describe('certificate policies on OpenSSL-issued chains', { timeout: 120_000 }, () => {
    /** keys and requests shared by every scenario: root, CA 1, CA 2, leaf */
    let base: string
    const names = ['root', 'ca1', 'ca2', 'leaf']

    beforeAll(async () => {
        // runOpenSSL joins its arguments into a shell line: no spaces in paths or names
        base = path.resolve(
            `${import.meta.dirname}/../../test-fixtures/tmp/policies-${randomUUID()}`,
        )
        fs.mkdirSync(base, { recursive: true })
        for (const name of names) {
            await runOpenSSL(
                [
                    'genpkey',
                    '-algorithm',
                    'EC',
                    '-pkeyopt',
                    'ec_paramgen_curve:P-256',
                    '-out',
                    `${base}/${name}.key`,
                ],
                base,
            )
        }
        await runOpenSSL(
            [
                'req', '-x509', '-new', '-key', `${base}/root.key`,
                '-subj', '/CN=PolicyRoot', '-days', '30',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-out', `${base}/root.pem`,
            ],
            base,
        )
        for (const [name, cn] of [
            ['ca1', 'PolicyCA1'],
            ['ca2', 'PolicyCA2'],
            ['leaf', 'leaf.example.com'],
        ]) {
            await runOpenSSL(
                [
                    'req', '-new', '-key', `${base}/${name}.key`,
                    '-subj', `/CN=${cn}`, '-out', `${base}/${name}.csr`,
                ],
                base,
            )
        }
    }, 120_000) // a dozen OpenSSL runs, each a docker container in CI

    /**
     * Issues the scenario's chain with OpenSSL. Everything stays in the shared folder
     * (files prefixed per scenario): with docker, OpenSSL writes the keys as root and
     * only it can read them.
     */
    async function issue(scenario: Scenario) {
        const id = randomUUID().slice(0, 8)
        const file = (name: string) =>
            name === 'root' ? `${base}/root.pem` : `${base}/${id}-${name}.pem`
        const sign = async (subject: string, issuer: string, config: string) => {
            fs.writeFileSync(`${base}/${id}-${subject}.cnf`, config)
            await runOpenSSL(
                [
                    'x509', '-req', '-in', `${base}/${subject}.csr`,
                    '-CA', file(issuer), '-CAkey', `${base}/${issuer}.key`,
                    '-days', '30', '-extfile', `${base}/${id}-${subject}.cnf`,
                    '-extensions', 'ext', '-out', file(subject),
                ],
                base,
            )
        }
        let issuer = 'root'
        for (const [index, ca] of scenario.cas.entries()) {
            const name = `ca${index + 1}`
            await sign(name, issuer, caConfig(ca))
            issuer = name
        }
        await sign('leaf', issuer, leafConfig(scenario.leafPolicies))

        const intermediates = scenario.cas.map((_, i) => `ca${i + 1}`)
        const untrusted = `${base}/${id}-untrusted.pem`
        fs.writeFileSync(
            untrusted,
            intermediates.map((n) => fs.readFileSync(file(n), 'utf8')).join(''),
        )
        const pem = (name: string) =>
            Certificate.fromPem(fs.readFileSync(file(name), 'utf8'))
        return {
            files: { root: file('root'), untrusted, leaf: file('leaf') },
            root: pem('root'),
            intermediates: intermediates.map(pem),
            leaf: pem('leaf'),
        }
    }

    async function opensslAccepts(
        files: { root: string; untrusted: string; leaf: string },
        scenario: Scenario,
    ) {
        const args = ['verify', '-policy_check']
        for (const policy of scenario.initialPolicySet ?? [ANY]) {
            args.push('-policy', policy)
        }
        if (scenario.initialExplicitPolicy) args.push('-explicit_policy')
        if (scenario.initialPolicyMappingInhibit) args.push('-inhibit_map')
        if (scenario.initialAnyPolicyInhibit) args.push('-inhibit_any')
        args.push('-CAfile', files.root, '-untrusted', files.untrusted, files.leaf)
        try {
            await runOpenSSL(args, base)
            return true
        } catch {
            return false
        }
    }

    for (const scenario of scenarios) {
        test(scenario.name, async () => {
            const chain = await issue(scenario)
            const result = await new CertificateValidator().validate(chain.leaf, {
                validateChain: true,
                trustAnchors: [{ certificate: chain.root }],
                otherCertificates: chain.intermediates,
                initialPolicySet: scenario.initialPolicySet,
                initialExplicitPolicy: scenario.initialExplicitPolicy,
                initialPolicyMappingInhibit: scenario.initialPolicyMappingInhibit,
                initialAnyPolicyInhibit: scenario.initialAnyPolicyInhibit,
            })

            expect(result.isValid, result.messages.join('; ')).toBe(scenario.valid)
            expect(await opensslAccepts(chain.files, scenario)).toBe(scenario.valid)
            if (scenario.valid && scenario.validPolicies) {
                expect([...(result.policyResult?.validPolicies ?? [])].sort()).toEqual(
                    [...scenario.validPolicies].sort(),
                )
            }
        })
    }
})
