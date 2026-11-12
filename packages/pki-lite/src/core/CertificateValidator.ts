import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { BasicConstraints } from '../x509/extensions/BasicConstraints.js'
import { NameConstraints } from '../x509/extensions/NameConstraints.js'
import { checkNameConstraints } from './NameConstraintsChecker.js'
import { namesMatch } from './NameMatching.js'
import { SubjectKeyIdentifier } from '../keys/SubjectKeyIdentifier.js'
import { SubjectAltName } from '../x509/extensions/SubjectAltName.js'
import { AuthorityKeyIdentifier } from '../x509/extensions/AuthorityKeyIdentifier.js'
import { CrlChecker } from './CrlChecker.js'
import { OIDs } from './OIDs.js'
import { ANY_POLICY, processPolicies } from './PolicyProcessor.js'
import { KeyUsage } from '../x509/extensions/KeyUsage.js'

/**
 * Enumeration of certificate validation status codes.
 */
/**
 * Certificate extensions that path validation processes, or that the library understands
 * and that place no constraint on the path (key identifiers, alternative names, CRL and
 * access locations, extended key usage, which applications check). A critical extension
 * not in this list makes the path invalid (RFC 5280 4.2).
 */
const PROCESSED_EXTENSIONS = new Set<string>([
    OIDs.EXTENSION.KEY_USAGE,
    OIDs.EXTENSION.BASIC_CONSTRAINTS,
    OIDs.EXTENSION.NAME_CONSTRAINTS,
    OIDs.EXTENSION.CERTIFICATE_POLICIES,
    OIDs.EXTENSION.POLICY_MAPPINGS,
    OIDs.EXTENSION.POLICY_CONSTRAINTS,
    OIDs.EXTENSION.INHIBIT_ANY_POLICY,
    OIDs.EXTENSION.SUBJECT_ALT_NAME,
    OIDs.EXTENSION.ISSUER_ALT_NAME,
    OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER,
    OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER,
    OIDs.EXTENSION.EXTENDED_KEY_USAGE,
    OIDs.EXTENSION.CRL_DISTRIBUTION_POINTS,
    OIDs.EXTENSION.FRESHEST_CRL,
    OIDs.EXTENSION.AUTHORITY_INFO_ACCESS,
])

export const CertificateValidationStatus = {
    VALID: 'VALID',
    EXPIRED: 'EXPIRED',
    NOT_YET_VALID: 'NOT_YET_VALID',
    REVOKED: 'REVOKED',
    UNKNOWN: 'UNKNOWN',
    SIGNATURE_INVALID: 'SIGNATURE_INVALID',
    ISSUER_UNKNOWN: 'ISSUER_UNKNOWN',
    CHAIN_INVALID: 'CHAIN_INVALID',
    CRL_UNAVAILABLE: 'CRL_UNAVAILABLE',
    OCSP_UNAVAILABLE: 'OCSP_UNAVAILABLE',
} as const

export type CertificateValidationStatus =
    (typeof CertificateValidationStatus)[keyof typeof CertificateValidationStatus]

/**
 * Represents the revocation status of a certificate.
 */
export interface RevocationStatus {
    /** Whether the certificate is revoked */
    isRevoked: boolean
    /** The source of revocation information (CRL or OCSP) */
    source: 'CRL' | 'OCSP' | 'NONE'
    /** The reason for revocation, if available */
    reason?: number
    /** The date when revocation was determined */
    revocationTime?: Date
    /** Additional information about the revocation check */
    details?: string
}

/**
 * Trust anchor for certificate validation.
 */
export interface TrustAnchor {
    /** The trusted root certificate */
    certificate: Certificate
    /**
     * Optional name constraints to apply to every certificate below this trust anchor,
     * in addition to any in the trust anchor's own certificate (when validating name
     * constraints).
     */
    nameConstraints?: NameConstraints
}

/**
 * Certificate chain information.
 */
export interface CertificateChain {
    /** Certificates in the chain from end-entity to root */
    certificates: Certificate[]
    /** Whether the chain was successfully built */
    isComplete: boolean
    /** Trust anchor used (if any) */
    trustAnchor?: TrustAnchor
}

/**
 * Policy validation result.
 */
export interface PolicyValidationResult {
    /** Whether policy validation passed */
    isValid: boolean
    /** Validated policy OIDs */
    validPolicies: string[]
    /** Policy violations */
    violations: string[]
}

/**
 * Options for certificate validation.
 */
export interface CertificateValidationOptions {
    /**
     * Check certificate revocation using CRLs, as RFC 5280 6.3 describes: a CRL counts only
     * if it is issued for the certificate (directly, or as an indirect CRL by a cRLIssuer
     * the certificate names), its issuingDistributionPoint scope covers the certificate, it
     * is current (thisUpdate <= time <= nextUpdate), it has no critical extension that is
     * not understood, and it is signed by a certificate with cRLSign whose path validates
     * (delta CRLs are applied on top). Every certificate below the trust anchor needs CRLs
     * covering all revocation reasons (or an OCSP answer, with `checkOCSP`); otherwise the
     * result is `CRL_UNAVAILABLE`. Applies when revocation data is passed to `validate`.
     */
    checkCRL?: boolean
    /** Check certificate revocation using OCSP */
    checkOCSP?: boolean
    /** Tolerance for time-based validations (in milliseconds) */
    timeTolerance?: number
    /** Custom validation date (defaults to current time) */
    validationTime?: Date
    /** Whether to perform signature validation */
    checkSignature?: boolean
    /** Trust anchors to use for chain validation */
    trustAnchors?: TrustAnchor[]
    /** Other certificates available for chain building */
    otherCertificates?: Certificate[]
    /** Whether to build and validate the full certificate chain */
    validateChain?: boolean
    /** Whether to enforce CA constraints and key usage */
    enforceCAConstraints?: boolean
    /**
     * Whether to enforce name constraints (RFC 5280 4.2.1.10): the `NameConstraints`
     * extension of every CA in the chain, and any given with the trust anchor, apply to the
     * certificates below them. On by default, as RFC 5280 requires of path validation; set
     * to `false` to skip the check. Part of chain validation (`validateChain`).
     */
    validateNameConstraints?: boolean
    /** Whether to process certificate policies (RFC 5280 6.1). On by default. */
    validatePolicies?: boolean
    /** Policy OIDs that must all be valid for the path (implies an explicit policy) */
    requiredPolicies?: string[]
    /** user-initial-policy-set: the path must be valid for at least one of these (default: any) */
    initialPolicySet?: string[]
    /** initial-explicit-policy: an acceptable policy is required even if no certificate asks for it */
    initialExplicitPolicy?: boolean
    /** initial-policy-mapping-inhibit: policy mappings are not allowed */
    initialPolicyMappingInhibit?: boolean
    /** initial-any-policy-inhibit: anyPolicy is not treated as a match */
    initialAnyPolicyInhibit?: boolean
}

/**
 * Result of certificate validation.
 */
export interface CertificateValidationResult {
    /** Overall validation status */
    status: CertificateValidationStatus
    /** Whether the certificate is valid */
    isValid: boolean
    /** Detailed validation messages */
    messages: string[]
    /** Revocation status information */
    revocationStatus: RevocationStatus
    /** The certificate that was validated */
    certificate: Certificate
    /** Validation timestamp */
    validatedAt: Date
    /** Certificate chain information (if chain validation was performed) */
    chain?: CertificateChain
    /** Policy validation result (if policy validation was performed) */
    policyResult?: PolicyValidationResult
    /** Diagnostic information for troubleshooting */
    diagnostics: {
        /** Validation steps performed */
        stepsPerformed: string[]
        /** Warnings encountered during validation */
        warnings: string[]
        /** Additional context information */
        context: Record<string, any>
    }
}

/**
 * A comprehensive certificate validator that checks certificate validity,
 * expiration, and revocation status using CRLs and OCSP responses.
 *
 * This class provides methods to validate X.509 certificates against
 * various criteria including:
 * - Certificate expiration dates
 * - Revocation status via Certificate Revocation Lists (CRLs)
 * - Revocation status via Online Certificate Status Protocol (OCSP)
 * - Certificate chain validation (when issuer certificates are provided)
 *
 * @example
 * ```typescript
 * const validator = new CertificateValidator()
 *
 * // Basic validation
 * const result = await validator.validate(certificate)
 *
 * // Validation with revocation checking
 * const result = await validator.validate(certificate, {
 *   checkCRL: true,
 *   checkOCSP: true
 * }, {
 *   crls: [crl1, crl2],
 *   ocspResponses: [ocspResponse]
 * })
 * ```
 */
export class CertificateValidator {
    /**
     * Validates a certificate against various criteria.
     *
     * @param certificate The certificate to validate
     * @param options Validation options
     * @param revocationData Optional revocation data (CRLs and OCSP responses)
     * @returns Promise resolving to validation result
     */
    async validate(
        certificate: Certificate,
        options: CertificateValidationOptions = {},
        revocationData?: {
            crls?: CertificateList[]
            ocspResponses?: OCSPResponse[]
            issuerCertificate?: Certificate
        },
    ): Promise<CertificateValidationResult> {
        const validationTime = options.validationTime || new Date()
        const timeTolerance = options.timeTolerance || 0
        const messages: string[] = []
        const diagnostics = {
            stepsPerformed: [] as string[],
            warnings: [] as string[],
            context: {} as Record<string, any>,
        }

        diagnostics.stepsPerformed.push('Starting certificate validation')
        diagnostics.context.validationTime = validationTime
        diagnostics.context.timeTolerance = timeTolerance

        // Initialize revocation status
        let revocationStatus: RevocationStatus = {
            isRevoked: false,
            source: 'NONE',
        }

        let chain: CertificateChain | undefined
        let policyResult: PolicyValidationResult | undefined

        // If chain validation is requested, build and validate the chain first
        if (options.validateChain && options.trustAnchors) {
            diagnostics.stepsPerformed.push('Building certificate chain')
            try {
                chain = await this.buildCertificateChain(certificate, options)
                diagnostics.context.chainLength = chain.certificates.length

                const chainValidationResult = await this.validateChain(
                    chain,
                    options,
                    revocationData,
                )

                // Update overall result based on chain validation
                if (!chainValidationResult.isValid) {
                    return {
                        status: chainValidationResult.status,
                        isValid: false,
                        messages: chainValidationResult.messages,
                        revocationStatus:
                            chainValidationResult.revocationStatus,
                        certificate,
                        validatedAt: new Date(),
                        chain,
                        policyResult: chainValidationResult.policyResult,
                        diagnostics,
                    }
                }

                // Use results from chain validation
                messages.push(...chainValidationResult.messages)
                revocationStatus = chainValidationResult.revocationStatus
                policyResult = chainValidationResult.policyResult

                // Merge diagnostics
                diagnostics.stepsPerformed.push(
                    ...chainValidationResult.diagnostics.stepsPerformed,
                )
                diagnostics.warnings.push(
                    ...chainValidationResult.diagnostics.warnings,
                )
                Object.assign(
                    diagnostics.context,
                    chainValidationResult.diagnostics.context,
                )

                return {
                    status: CertificateValidationStatus.VALID,
                    isValid: true,
                    messages,
                    revocationStatus,
                    certificate,
                    validatedAt: new Date(),
                    chain,
                    policyResult,
                    diagnostics,
                }
            } catch (error) {
                diagnostics.warnings.push(`Chain building failed: ${error}`)
                messages.push(`Certificate chain validation failed: ${error}`)
                return {
                    status: CertificateValidationStatus.CHAIN_INVALID,
                    isValid: false,
                    messages,
                    revocationStatus,
                    certificate,
                    validatedAt: new Date(),
                    chain,
                    diagnostics,
                }
            }
        }

        // Fallback to single certificate validation (existing logic)
        diagnostics.stepsPerformed.push('Checking certificate validity period')

        // Check certificate validity period first
        const validityResult = this.checkValidityPeriod(
            certificate,
            validationTime,
            timeTolerance,
        )
        if (validityResult.status !== CertificateValidationStatus.VALID) {
            // If certificate is expired or not yet valid, return immediately
            // Don't check revocation status for invalid certificates
            diagnostics.stepsPerformed.push(
                'Certificate validity period check failed',
            )
            return {
                status: validityResult.status,
                isValid: false,
                messages: [validityResult.message],
                revocationStatus: {
                    isRevoked: false,
                    source: 'NONE',
                },
                certificate,
                validatedAt: new Date(),
                diagnostics,
            }
        }

        diagnostics.stepsPerformed.push('Certificate is within validity period')

        // Certificate is within validity period, now check revocation if requested
        let finalStatus: CertificateValidationStatus =
            CertificateValidationStatus.VALID

        // Check revocation status if requested and data is available
        if ((options.checkCRL || options.checkOCSP) && revocationData) {
            diagnostics.stepsPerformed.push('Checking revocation status')
            const revocationResult = await this.checkRevocationStatus(
                certificate,
                revocationData,
                options,
                // without chain validation, the issuer given is taken on trust
                revocationData.issuerCertificate
                    ? [revocationData.issuerCertificate]
                    : [],
            )

            revocationStatus = revocationResult

            if (revocationResult.undetermined) {
                finalStatus = CertificateValidationStatus.CRL_UNAVAILABLE
                messages.push(
                    `Revocation status could not be determined: ${revocationResult.details}`,
                )
            } else if (revocationResult.isRevoked) {
                finalStatus = CertificateValidationStatus.REVOKED
                messages.push(
                    `Certificate is revoked (${revocationResult.source})${
                        revocationResult.details
                            ? `: ${revocationResult.details}`
                            : ''
                    }`,
                )
                diagnostics.stepsPerformed.push(
                    'Certificate revocation detected',
                )
            } else {
                diagnostics.stepsPerformed.push('Certificate is not revoked')
            }
        }

        return {
            status: finalStatus,
            isValid: finalStatus === CertificateValidationStatus.VALID,
            messages,
            revocationStatus,
            certificate,
            validatedAt: new Date(),
            chain,
            policyResult,
            diagnostics,
        }
    }

    /**
     * Builds a certificate chain from the end-entity certificate to a trusted root.
     */
    async buildCertificateChain(
        certificate: Certificate,
        options: CertificateValidationOptions,
    ): Promise<CertificateChain> {
        const chain: Certificate[] = [certificate]
        const availableCerts = options.otherCertificates || []
        const trustAnchors = options.trustAnchors || []
        const seenCerts = new Set<string>() // Track certificates to prevent loops

        let current = certificate
        let trustAnchor: TrustAnchor | undefined

        // Add current certificate to seen set
        const currentKey = this.getCertificateKey(current)
        seenCerts.add(currentKey)

        // Build chain by following issuer relationships
        while (true) {
            // Check if current certificate is self-signed (root)
            if (await this.isSelfSigned(current)) {
                // Check if this root is a trust anchor
                trustAnchor = trustAnchors.find((ta) =>
                    this.certificatesEqual(ta.certificate, current),
                )
                break
            }

            // Find issuer certificate
            const issuer: Certificate | undefined =
                this.findIssuer(current, [
                    ...availableCerts,
                    ...trustAnchors.map((ta) => ta.certificate),
                ]) ?? (await current.requestIssuerCertificate())

            if (!issuer) {
                // Chain is incomplete
                break
            }

            // Check for loops before adding issuer
            const issuerKey = this.getCertificateKey(issuer)
            if (seenCerts.has(issuerKey)) {
                throw new Error(
                    'Certificate chain contains a loop - circular chain detected',
                )
            }

            // Check if issuer is a trust anchor
            const issuerTrustAnchor = trustAnchors.find((ta) =>
                this.certificatesEqual(ta.certificate, issuer),
            )

            if (issuerTrustAnchor) {
                // Found trust anchor, add to chain and stop
                chain.push(issuer)
                trustAnchor = issuerTrustAnchor
                break
            }

            // Add intermediate certificate to chain and track it
            chain.push(issuer)
            seenCerts.add(issuerKey)
            current = issuer

            // Prevent extremely long chains
            if (chain.length > 10) {
                throw new Error(
                    'Certificate chain too long (maximum 10 certificates allowed)',
                )
            }
        }

        const isComplete = trustAnchor !== undefined

        return {
            certificates: chain,
            isComplete,
            trustAnchor,
        }
    }

    /**
     * Validates a complete certificate chain.
     */
    async validateChain(
        chain: CertificateChain,
        options: CertificateValidationOptions,
        revocationData?: {
            crls?: CertificateList[]
            ocspResponses?: OCSPResponse[]
            issuerCertificate?: Certificate
        },
    ): Promise<CertificateValidationResult> {
        const messages: string[] = []
        const diagnostics = {
            stepsPerformed: ['Validating certificate chain'],
            warnings: [] as string[],
            context: { chainLength: chain.certificates.length },
        }

        if (!chain.isComplete) {
            return {
                status: CertificateValidationStatus.CHAIN_INVALID,
                isValid: false,
                messages: [
                    'Certificate chain is incomplete - no trust anchor found',
                ],
                revocationStatus: { isRevoked: false, source: 'NONE' },
                certificate: chain.certificates[0],
                validatedAt: new Date(),
                chain,
                diagnostics,
            }
        }

        const validationTime = options.validationTime || new Date()
        const timeTolerance = options.timeTolerance || 0

        // Validate each certificate in the chain
        // Enforce pathLenConstraint for each CA certificate in the chain
        for (let i = 0; i < chain.certificates.length; i++) {
            const cert = chain.certificates[i]
            const isEndEntity = i === 0
            const isRoot = i === chain.certificates.length - 1

            diagnostics.stepsPerformed.push(
                `Validating certificate ${i + 1} of ${chain.certificates.length}`,
            )

            // Check validity period
            const validityResult = this.checkValidityPeriod(
                cert,
                validationTime,
                timeTolerance,
            )
            if (validityResult.status !== CertificateValidationStatus.VALID) {
                return {
                    status: validityResult.status,
                    isValid: false,
                    messages: [
                        `Certificate ${i + 1} in chain: ${validityResult.message}`,
                    ],
                    revocationStatus: { isRevoked: false, source: 'NONE' },
                    certificate: chain.certificates[0],
                    validatedAt: new Date(),
                    chain,
                    diagnostics,
                }
            }

            // RFC 5280 6.1.4 (o), 6.1.5 (f): a critical extension that is not processed
            // makes the path invalid (the trust anchor's extensions are not processed)
            if (!isRoot) {
                const unknown = cert.tbsCertificate.extensions?.find(
                    (extension) =>
                        extension.critical &&
                        !PROCESSED_EXTENSIONS.has(extension.extnID.value),
                )
                if (unknown) {
                    return {
                        status: CertificateValidationStatus.CHAIN_INVALID,
                        isValid: false,
                        messages: [
                            `Certificate ${i + 1} has an unrecognised critical extension ${unknown.extnID.value}`,
                        ],
                        revocationStatus: { isRevoked: false, source: 'NONE' },
                        certificate: chain.certificates[0],
                        validatedAt: new Date(),
                        chain,
                        diagnostics,
                    }
                }
            }

            // For non-root certificates, verify issuer relationship and signature
            if (!isRoot) {
                const issuer = chain.certificates[i + 1]

                // Verify issuer-subject relationship
                if (!this.verifyIssuerSubjectRelationship(cert, issuer)) {
                    return {
                        status: CertificateValidationStatus.CHAIN_INVALID,
                        isValid: false,
                        messages: [
                            `Certificate ${i + 1} was not issued by certificate ${i + 2}`,
                        ],
                        revocationStatus: { isRevoked: false, source: 'NONE' },
                        certificate: chain.certificates[0],
                        validatedAt: new Date(),
                        chain,
                        diagnostics,
                    }
                }

                // Verify signature (if requested)
                if (options.checkSignature) {
                    try {
                        const signatureValid = await cert.isIssuedBy(issuer)
                        if (!signatureValid) {
                            return {
                                status: CertificateValidationStatus.SIGNATURE_INVALID,
                                isValid: false,
                                messages: [
                                    `Certificate ${i + 1} signature verification failed`,
                                ],
                                revocationStatus: {
                                    isRevoked: false,
                                    source: 'NONE',
                                },
                                certificate: chain.certificates[0],
                                validatedAt: new Date(),
                                chain,
                                diagnostics,
                            }
                        }
                    } catch (error) {
                        // fail closed: a signature that cannot be verified (unsupported
                        // algorithm, malformed key or signature) is not a valid one
                        return {
                            status: CertificateValidationStatus.SIGNATURE_INVALID,
                            isValid: false,
                            messages: [
                                `Certificate ${i + 1} signature could not be verified: ${error}`,
                            ],
                            revocationStatus: {
                                isRevoked: false,
                                source: 'NONE',
                            },
                            certificate: chain.certificates[0],
                            validatedAt: new Date(),
                            chain,
                            diagnostics,
                        }
                    }
                }
            }

            // Check CA constraints for non-end-entity certificates
            if (!isEndEntity && options.enforceCAConstraints) {
                const caValidationResult =
                    this.validateCertificateAuthority(cert)
                if (!caValidationResult.isValid) {
                    return {
                        status: CertificateValidationStatus.CHAIN_INVALID,
                        isValid: false,
                        messages: [
                            `Certificate ${i + 1} CA constraints violation: ${caValidationResult.message}`,
                        ],
                        revocationStatus: { isRevoked: false, source: 'NONE' },
                        certificate: chain.certificates[0],
                        validatedAt: new Date(),
                        chain,
                        diagnostics,
                    }
                }

                // Enforce pathLenConstraint for CA certificates (RFC 5280 section 4.2.1.9)
                // Only applies to CA certificates (not end-entity or root)
                // pathLenConstraint limits the number of non-self-issued intermediate CAs below this CA
                // i = current cert index; certs[0] = leaf, certs[n-1] = root
                // For each CA, count the number of CA certs between it and the leaf (excluding itself)
                const extensions = cert.tbsCertificate.extensions
                if (extensions) {
                    for (const ext of extensions) {
                        if (
                            ext.extnID.value ===
                            OIDs.EXTENSION.BASIC_CONSTRAINTS
                        ) {
                            const basicConstraints =
                                ext.extnValue.parseAs(BasicConstraints)
                            if (
                                typeof basicConstraints.pathLenConstraint ===
                                'number'
                            ) {
                                // Count the number of non-self-issued CA certs between this CA and the leaf
                                // RFC 5280 4.2.1.9: only intermediate certificates count,
                                // never the end certificate (index 0), even if it is a CA
                                let nonSelfIssuedCAs = 0
                                for (let j = i - 1; j >= 1; j--) {
                                    const belowCert = chain.certificates[j]
                                    // Only count CA certs
                                    const belowExts =
                                        belowCert.tbsCertificate.extensions
                                    let isBelowCA = false
                                    if (belowExts) {
                                        for (const belowExt of belowExts) {
                                            if (
                                                belowExt.extnID.value ===
                                                OIDs.EXTENSION.BASIC_CONSTRAINTS
                                            ) {
                                                const belowBC =
                                                    belowExt.extnValue.parseAs(
                                                        BasicConstraints,
                                                    )
                                                if (belowBC.cA) {
                                                    isBelowCA = true
                                                }
                                            }
                                        }
                                    }
                                    // Only count CAs that are not self-issued (subject and
                                    // issuer names equal, e.g. a key rollover); being
                                    // self-signed is not the test
                                    if (
                                        isBelowCA &&
                                        !this.isSelfIssued(belowCert)
                                    ) {
                                        nonSelfIssuedCAs++
                                    }
                                }
                                if (
                                    nonSelfIssuedCAs >
                                    basicConstraints.pathLenConstraint
                                ) {
                                    return {
                                        status: CertificateValidationStatus.CHAIN_INVALID,
                                        isValid: false,
                                        messages: [
                                            `Certificate ${i + 1} pathLenConstraint violation: ${nonSelfIssuedCAs} non-self-issued CA certificates below, but pathLenConstraint is ${basicConstraints.pathLenConstraint}`,
                                        ],
                                        revocationStatus: {
                                            isRevoked: false,
                                            source: 'NONE',
                                        },
                                        certificate: chain.certificates[0],
                                        validatedAt: new Date(),
                                        chain,
                                        diagnostics,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Name constraints (RFC 5280 6.1): those of every CA in the path, and any given
        // with the trust anchor, apply to the certificates below them
        if (options.validateNameConstraints !== false) {
            const violation = this.checkChainNameConstraints(chain)

            if (violation) {
                return {
                    status: CertificateValidationStatus.CHAIN_INVALID,
                    isValid: false,
                    messages: [`Name constraints violation: ${violation}`],
                    revocationStatus: { isRevoked: false, source: 'NONE' },
                    certificate: chain.certificates[0],
                    validatedAt: new Date(),
                    chain,
                    diagnostics,
                }
            }
        }

        // Validate policies if requested
        let policyResult: PolicyValidationResult | undefined
        if (options.validatePolicies !== false) {
            policyResult = this.validatePolicies(chain, options)
            if (!policyResult.isValid) {
                return {
                    status: CertificateValidationStatus.CHAIN_INVALID,
                    isValid: false,
                    messages: [
                        `Policy validation failed: ${policyResult.violations.join(', ')}`,
                    ],
                    revocationStatus: { isRevoked: false, source: 'NONE' },
                    certificate: chain.certificates[0],
                    validatedAt: new Date(),
                    chain,
                    policyResult,
                    diagnostics,
                }
            }
        }

        // Check revocation status for all certificates if requested
        let revocationStatus: RevocationStatus = {
            isRevoked: false,
            source: 'NONE',
        }
        if ((options.checkCRL || options.checkOCSP) && revocationData) {
            for (let i = 0; i < chain.certificates.length - 1; i++) {
                // Skip root
                const cert = chain.certificates[i]
                const certRevocationStatus = await this.checkRevocationStatus(
                    cert,
                    revocationData,
                    options,
                    chain.certificates.slice(i + 1),
                )

                if (certRevocationStatus.undetermined) {
                    return {
                        status: CertificateValidationStatus.CRL_UNAVAILABLE,
                        isValid: false,
                        messages: [
                            `Revocation status of certificate ${i + 1} in chain could not be determined: ${certRevocationStatus.details}`,
                        ],
                        revocationStatus: certRevocationStatus,
                        certificate: chain.certificates[0],
                        validatedAt: new Date(),
                        chain,
                        policyResult,
                        diagnostics,
                    }
                }

                if (certRevocationStatus.isRevoked) {
                    return {
                        status: CertificateValidationStatus.REVOKED,
                        isValid: false,
                        messages: [
                            `Certificate ${i + 1} in chain is revoked: ${certRevocationStatus.details}`,
                        ],
                        revocationStatus: certRevocationStatus,
                        certificate: chain.certificates[0],
                        validatedAt: new Date(),
                        chain,
                        policyResult,
                        diagnostics,
                    }
                }

                // Update revocation status with most specific information
                if (certRevocationStatus.source !== 'NONE') {
                    revocationStatus = certRevocationStatus
                }
            }
        }

        messages.push('Certificate chain validation successful')
        diagnostics.stepsPerformed.push(
            'Certificate chain validation completed successfully',
        )

        return {
            status: CertificateValidationStatus.VALID,
            isValid: true,
            messages,
            revocationStatus,
            certificate: chain.certificates[0],
            validatedAt: new Date(),
            chain,
            policyResult,
            diagnostics,
        }
    }
    private checkValidityPeriod(
        certificate: Certificate,
        validationTime: Date,
        timeTolerance: number,
    ): { status: CertificateValidationStatus; message: string } {
        const validity = certificate.tbsCertificate.validity
        const notBefore = validity.notBefore
        const notAfter = validity.notAfter

        const adjustedValidationTime = new Date(
            validationTime.getTime() + timeTolerance,
        )
        const adjustedValidationTimeBefore = new Date(
            validationTime.getTime() - timeTolerance,
        )

        if (adjustedValidationTime < notBefore) {
            return {
                status: CertificateValidationStatus.NOT_YET_VALID,
                message: `Certificate is not yet valid. Valid from: ${notBefore.toISOString()}`,
            }
        }

        if (adjustedValidationTimeBefore > notAfter) {
            return {
                status: CertificateValidationStatus.EXPIRED,
                message: `Certificate has expired. Valid until: ${notAfter.toISOString()}`,
            }
        }

        return {
            status: CertificateValidationStatus.VALID,
            message: 'Certificate is within its validity period',
        }
    }

    /**
     * Checks the revocation status of a certificate using available CRLs and OCSP responses.
     *
     * @param trustedSigners certificates trusted to sign CRLs without validating them
     *   again: the trust anchors, and the certificates above this one in the path being
     *   validated (which that validation covers)
     */
    private async checkRevocationStatus(
        certificate: Certificate,
        revocationData: {
            crls?: CertificateList[]
            ocspResponses?: OCSPResponse[]
            issuerCertificate?: Certificate
        },
        options: CertificateValidationOptions,
        trustedSigners: Certificate[],
    ): Promise<RevocationStatus & { undetermined?: boolean }> {
        // Check OCSP responses first (more current)
        if (options.checkOCSP && revocationData.ocspResponses) {
            const ocspResult = this.checkOCSPRevocation(
                certificate,
                revocationData.ocspResponses,
            )
            if (ocspResult.source !== 'NONE') {
                return ocspResult
            }
        }

        // Check CRLs (RFC 5280 6.3)
        if (options.checkCRL) {
            const anchors = (options.trustAnchors ?? []).map(
                (anchor) => anchor.certificate,
            )
            const checker = new CrlChecker({
                crls: revocationData.crls ?? [],
                certificates: [
                    ...trustedSigners,
                    ...(revocationData.issuerCertificate
                        ? [revocationData.issuerCertificate]
                        : []),
                    ...(options.otherCertificates ?? []),
                    ...anchors,
                ],
                trustAnchors: [...anchors, ...trustedSigners],
                time: options.validationTime ?? new Date(),
                validateSigner: (signer) =>
                    this.validateCrlSigner(signer, options, revocationData),
            })
            const result = await checker.check(certificate)
            if (result.status === 'revoked') {
                return {
                    isRevoked: true,
                    source: 'CRL',
                    reason: result.reason,
                    revocationTime: result.revocationTime,
                    details: `${result.details}${
                        result.reason !== undefined
                            ? ` with reason: ${this.getRevocationReasonText(result.reason)}`
                            : ''
                    }`,
                }
            }
            if (result.status === 'good') {
                return {
                    isRevoked: false,
                    source: 'CRL',
                    details: result.details,
                }
            }
            return {
                isRevoked: false,
                source: 'NONE',
                details: result.details,
                undetermined: true,
            }
        }

        return {
            isRevoked: false,
            source: 'NONE',
            details: 'No revocation information available',
        }
    }

    /** CRL signers whose path is being validated (the recursion guard of validateCrlSigner). */
    private readonly crlSignersInProgress = new Set<Certificate>()

    /**
     * Validates the certification path of a CRL signer outside the path being validated
     * (RFC 5280 6.3.3 (f)): to the same trust anchors, with its own revocation status.
     */
    private async validateCrlSigner(
        signer: Certificate,
        options: CertificateValidationOptions,
        revocationData: { crls?: CertificateList[] },
    ): Promise<boolean> {
        if (!options.trustAnchors?.length) return false
        // A CRL issuer's own certificate can be covered by the CRL it signs (an indirect
        // CRL, PKITS 4.14.30): its path, still being validated further up, decides
        for (const inProgress of this.crlSignersInProgress) {
            if (inProgress.equals(signer)) return true
        }
        this.crlSignersInProgress.add(signer)
        try {
            const result = await this.validate(
                signer,
                {
                    ...options,
                    validateChain: true,
                    // the user's policy requirements are for the certificate's path
                    requiredPolicies: undefined,
                    initialPolicySet: undefined,
                    initialExplicitPolicy: false,
                },
                { crls: revocationData.crls },
            )
            return result.isValid
        } finally {
            this.crlSignersInProgress.delete(signer)
        }
    }

    /**
     * Checks certificate revocation using OCSP responses.
     */
    private checkOCSPRevocation(
        certificate: Certificate,
        ocspResponses: OCSPResponse[],
    ): RevocationStatus {
        for (const ocspResponse of ocspResponses) {
            const basicResponse = ocspResponse.getBasicOCSPResponse()
            if (!basicResponse) {
                continue
            }

            for (const singleResponse of basicResponse.tbsResponseData
                .responses) {
                // Compare certificate serial numbers
                const responseCertSerial = singleResponse.certID.serialNumber
                const certSerial = certificate.tbsCertificate.serialNumber

                if (responseCertSerial.equals(certSerial)) {
                    const certStatus = singleResponse.certStatus

                    if (certStatus.status === 'revoked') {
                        return {
                            isRevoked: true,
                            source: 'OCSP',
                            reason: certStatus.revocationReason,
                            revocationTime: certStatus.revocationTime,
                            details: `Certificate revoked via OCSP${
                                certStatus.revocationReason !== undefined
                                    ? ` with reason: ${this.getRevocationReasonText(certStatus.revocationReason)}`
                                    : ''
                            }`,
                        }
                    } else if (certStatus.status === 'good') {
                        return {
                            isRevoked: false,
                            source: 'OCSP',
                            details: 'Certificate confirmed as valid via OCSP',
                        }
                    } else {
                        return {
                            isRevoked: false,
                            source: 'OCSP',
                            details: 'Certificate status unknown via OCSP',
                        }
                    }
                }
            }
        }

        return {
            isRevoked: false,
            source: 'NONE',
        }
    }

    /**
     * Gets human-readable text for revocation reason codes.
     */
    private getRevocationReasonText(reason: number): string {
        const reasons = {
            0: 'unspecified',
            1: 'keyCompromise',
            2: 'cACompromise',
            3: 'affiliationChanged',
            4: 'superseded',
            5: 'cessationOfOperation',
            6: 'certificateHold',
            8: 'removeFromCRL',
            9: 'privilegeWithdrawn',
            10: 'aACompromise',
        }

        return reasons[reason as keyof typeof reasons] || `unknown(${reason})`
    }

    /**
     * Checks if a certificate is self-signed (root certificate).
     */
    private async isSelfSigned(certificate: Certificate): Promise<boolean> {
        const subject = certificate.tbsCertificate.subject
        const issuer = certificate.tbsCertificate.issuer

        // Basic check: subject matches issuer
        return (
            namesMatch(subject, issuer) &&
            (await certificate.isIssuedBy(certificate))
        )
    }

    /**
     * Finds the issuer certificate for a given certificate.
     */
    private findIssuer(
        certificate: Certificate,
        candidates: Certificate[],
    ): Certificate | undefined {
        const issuerName = certificate.tbsCertificate.issuer

        for (const candidate of candidates) {
            const candidateSubject = candidate.tbsCertificate.subject

            // Check if subject name matches issuer name (RFC 5280 7.1)
            if (namesMatch(candidateSubject, issuerName)) {
                // Additional check: verify key identifiers if present
                if (this.verifyKeyIdentifiers(certificate, candidate)) {
                    return candidate
                }
            }
        }

        return undefined
    }

    /**
     * Verifies key identifiers match between certificate and issuer.
     */
    private verifyKeyIdentifiers(
        certificate: Certificate,
        issuer: Certificate,
    ): boolean {
        // If no key identifier extensions are present, assume match
        const authKeyId =
            this.getAuthorityKeyIdentifier(certificate)?.keyIdentifier
        const subjKeyId = this.getSubjectKeyIdentifier(issuer)

        if (!authKeyId || !subjKeyId) {
            return true // Cannot verify, assume valid
        }

        return authKeyId.equals(subjKeyId)
    }

    /**
     * Gets the Authority Key Identifier from a certificate.
     */
    private getAuthorityKeyIdentifier(
        certificate: Certificate,
    ): AuthorityKeyIdentifier | undefined {
        const extensions = certificate.tbsCertificate.extensions
        if (!extensions) return undefined

        for (const ext of extensions) {
            if (ext.extnID.value === OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER) {
                return ext.extnValue.parseAs(AuthorityKeyIdentifier)
            }
        }

        return undefined
    }

    /**
     * Gets the Subject Key Identifier from a certificate.
     */
    private getSubjectKeyIdentifier(
        certificate: Certificate,
    ): SubjectKeyIdentifier | undefined {
        const extensions = certificate.tbsCertificate.extensions
        if (!extensions) return undefined

        for (const ext of extensions) {
            if (ext.extnID.value === OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER) {
                return ext.extnValue.parseAs(SubjectKeyIdentifier)
            }
        }

        return undefined
    }

    /**
     * Gets a unique key for a certificate to detect loops.
     */
    private getCertificateKey(certificate: Certificate): string {
        // Use serial number + issuer as unique key
        const serial = certificate.tbsCertificate.serialNumber.toHexString()
        const issuer = certificate.tbsCertificate.issuer.toHumanString()
        const validity = certificate.tbsCertificate.validity.toHumanString()
        return `${serial}:${issuer}:${validity}`
    }

    /**
     * Compares two certificates for equality.
     */
    private certificatesEqual(cert1: Certificate, cert2: Certificate): boolean {
        // Compare by serializing to DER and comparing bytes
        try {
            return cert1.equals(cert2)
        } catch (error) {
            return cert1.getIssuerSerial().equals(cert2.getIssuerSerial())
        }
    }

    /**
     * Verifies the issuer-subject relationship between two certificates.
     */
    private verifyIssuerSubjectRelationship(
        certificate: Certificate,
        issuer: Certificate,
    ): boolean {
        return namesMatch(
            certificate.tbsCertificate.issuer,
            issuer.tbsCertificate.subject,
        )
    }

    /**
     * Validates Certificate Authority constraints and key usage.
     */
    private validateCertificateAuthority(certificate: Certificate): {
        isValid: boolean
        message: string
    } {
        const extensions = certificate.tbsCertificate.extensions
        if (!extensions) {
            return {
                isValid: false,
                message: 'CA certificate must have extensions',
            }
        }

        let basicConstraintsFound = false
        let isCA = false
        let pathLenConstraint: number | undefined

        for (const ext of extensions) {
            // Basic Constraints OID: 2.5.29.19
            if (ext.extnID.value === OIDs.EXTENSION.BASIC_CONSTRAINTS) {
                basicConstraintsFound = true
                // Parse Basic Constraints extension properly
                const basicConstraints = ext.extnValue.parseAs(BasicConstraints)

                if (basicConstraints.cA) {
                    isCA = true
                    pathLenConstraint = basicConstraints.pathLenConstraint
                } else {
                    isCA = false
                }
                break
            }
        }

        if (!basicConstraintsFound) {
            return {
                isValid: false,
                message: 'CA certificate must have Basic Constraints extension',
            }
        }

        if (!isCA) {
            return {
                isValid: false,
                message: 'Certificate is not marked as CA in Basic Constraints',
            }
        }

        // Validate pathLenConstraint if present (must be >= 0)
        if (typeof pathLenConstraint !== 'undefined' && pathLenConstraint < 0) {
            return {
                isValid: false,
                message: `Invalid pathLenConstraint: ${pathLenConstraint}`,
            }
        }

        // Key Usage extension check (if present)
        for (const ext of extensions) {
            // Key Usage OID: 2.5.29.15
            if (ext.extnID.value === OIDs.EXTENSION.KEY_USAGE) {
                const keyUsage = ext.extnValue.parseAs(KeyUsage)
                // RFC 5280 4.2.1.3 and 6.1.4 (n): a CA that signs certificates must
                // assert keyCertSign (digitalSignature is not required)
                if (!keyUsage.keyCertSign) {
                    return {
                        isValid: false,
                        message:
                            'CA certificate must have keyCertSign key usage',
                    }
                }
            }
        }

        // Note: Enforcing the pathLenConstraint limit on subordinate CA certificates should be done during chain validation.

        return {
            isValid: true,
            message: 'CA constraints validated successfully',
        }
    }

    /**
     * Checks the certificates of a chain against name constraints (RFC 5280 6.1.3 (b)
     * and (c), 6.1.4 (g)). The constraints of each CA in the path, and any supplied with
     * the trust anchor, apply to every certificate below it. A self-issued certificate in
     * the middle of the path (e.g. a CA key rollover) is exempt, but the last one is not.
     *
     * @returns a description of the first violation, or undefined if there is none
     */
    private checkChainNameConstraints(
        chain: CertificateChain,
    ): string | undefined {
        const certificates = chain.certificates
        const last = certificates.length - 1

        // [constraints, who they came from, how many certificates below them]
        const sources: [NameConstraints, string, number][] = []
        for (let index = 1; index < certificates.length; index++) {
            const ca = certificates[index]
            const extension = ca.getExtensionByOid(
                OIDs.EXTENSION.NAME_CONSTRAINTS,
            )
            if (!extension) continue
            try {
                sources.push([
                    extension.extnValue.parseAs(NameConstraints),
                    ca.tbsCertificate.subject.toHumanString(),
                    index,
                ])
            } catch (error) {
                return `cannot read the name constraints of '${ca.tbsCertificate.subject.toHumanString()}': ${error instanceof Error ? error.message : String(error)}`
            }
        }

        const anchor = chain.trustAnchor
        if (anchor?.nameConstraints) {
            // everything below the trust anchor (its own certificate, when in the chain, last)
            const below = this.certificatesEqual(
                certificates[last],
                anchor.certificate,
            )
                ? last
                : certificates.length
            sources.push([
                anchor.nameConstraints,
                `trust anchor '${anchor.certificate.tbsCertificate.subject.toHumanString()}'`,
                below,
            ])
        }

        for (const [constraints, source, below] of sources) {
            for (let index = 0; index < below; index++) {
                const certificate = certificates[index]
                const isIntermediate = index > 0 && index < last
                if (isIntermediate && this.isSelfIssued(certificate)) continue

                const violation = checkNameConstraints(certificate, constraints)
                if (violation) {
                    return `${violation.message} (certificate '${certificate.tbsCertificate.subject.toHumanString()}', constrained by ${source.startsWith('trust') ? source : `'${source}'`})`
                }
            }
        }
        return undefined
    }

    /** Whether a certificate's issuer and subject are the same name. */
    private isSelfIssued(certificate: Certificate): boolean {
        return namesMatch(
            certificate.tbsCertificate.issuer,
            certificate.tbsCertificate.subject,
        )
    }

    private extractSubjectAltNames(certificate: Certificate): SubjectAltName[] {
        return certificate.getSubjectAltNames()
    }

    /**
     * Extracts the common name (CN) from a certificate's subject.
     */
    private extractCommonName(certificate: Certificate): string | undefined {
        return certificate.getCommonName()
    }

    /**
     * Certificate policy processing (RFC 5280 6.1) of the path below the trust anchor.
     */
    private validatePolicies(
        chain: CertificateChain,
        options: CertificateValidationOptions,
    ): PolicyValidationResult {
        const certificates = chain.certificates
        const last = certificates[certificates.length - 1]
        const path =
            chain.trustAnchor &&
            this.certificatesEqual(last, chain.trustAnchor.certificate)
                ? certificates.slice(0, -1)
                : certificates

        const required = options.requiredPolicies ?? []
        const result = processPolicies(
            path,
            (certificate) => this.isSelfIssued(certificate),
            {
                initialPolicySet: options.initialPolicySet,
                initialExplicitPolicy:
                    options.initialExplicitPolicy || required.length > 0,
                initialPolicyMappingInhibit:
                    options.initialPolicyMappingInhibit,
                initialAnyPolicyInhibit: options.initialAnyPolicyInhibit,
            },
        )

        const violations = [...result.violations]
        if (required.length > 0) {
            // every required policy must be valid for the path (anyPolicy covers all)
            const valid = new Set(result.validPolicies)
            for (const policy of required) {
                if (!valid.has(policy) && !valid.has(ANY_POLICY)) {
                    violations.push(`Required policy not found: ${policy}`)
                }
            }
        }
        return {
            isValid: violations.length === 0,
            validPolicies: result.validPolicies,
            violations,
        }
    }
}
