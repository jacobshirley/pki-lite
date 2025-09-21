import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { BasicConstraints } from '../x509/extensions/BasicConstraints.js'
import { NameConstraints } from '../x509/extensions/NameConstraints.js'
import { SubjectKeyIdentifier } from '../keys/SubjectKeyIdentifier.js'
import { SubjectAltName } from '../x509/extensions/SubjectAltName.js'
import { AuthorityKeyIdentifier } from '../x509/extensions/AuthorityKeyIdentifier.js'
import { CRLReason } from '../x509/CRLReason.js'
import { OIDs } from './OIDs.js'
import { KeyUsage } from '../x509/extensions/KeyUsage.js'

/**
 * Enumeration of certificate validation status codes.
 */
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
    /** Optional name constraints to apply */
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
    /** Check certificate revocation using CRLs */
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
    /** Whether to validate name constraints */
    validateNameConstraints?: boolean
    /** Whether to validate certificate policies */
    validatePolicies?: boolean
    /** Required policy OIDs (if any) */
    requiredPolicies?: string[]
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
            )

            revocationStatus = revocationResult

            if (revocationResult.isRevoked) {
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
                        diagnostics.warnings.push(
                            `Signature verification failed for certificate ${i + 1}: ${error}`,
                        )
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
                                let nonSelfIssuedCAs = 0
                                for (let j = i - 1; j >= 0; j--) {
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
                                    // Only count if not self-issued and is CA
                                    if (
                                        isBelowCA &&
                                        !(await this.isSelfSigned(belowCert))
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

        // Check name constraints if trust anchor has them
        if (
            options.validateNameConstraints &&
            chain.trustAnchor?.nameConstraints
        ) {
            const nameConstraintResult = this.validateNameConstraints(
                chain.certificates[0],
                chain.trustAnchor.nameConstraints,
            )

            if (!nameConstraintResult.isValid) {
                return {
                    status: CertificateValidationStatus.CHAIN_INVALID,
                    isValid: false,
                    messages: [
                        `Name constraints violation: ${nameConstraintResult.message}`,
                    ],
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
        if (options.validatePolicies) {
            policyResult = this.validatePolicies(
                chain,
                options.requiredPolicies,
            )
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
                )

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
     */
    private async checkRevocationStatus(
        certificate: Certificate,
        revocationData: {
            crls?: CertificateList[]
            ocspResponses?: OCSPResponse[]
            issuerCertificate?: Certificate
        },
        options: CertificateValidationOptions,
    ): Promise<RevocationStatus> {
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

        // Check CRLs
        if (options.checkCRL && revocationData.crls) {
            const crlResult = this.checkCRLRevocation(
                certificate,
                revocationData.crls,
            )
            if (crlResult.source !== 'NONE') {
                return crlResult
            }
        }

        return {
            isRevoked: false,
            source: 'NONE',
            details: 'No revocation information available',
        }
    }

    /**
     * Checks certificate revocation using CRLs.
     */
    private checkCRLRevocation(
        certificate: Certificate,
        crls: CertificateList[],
    ): RevocationStatus {
        const serialNumber = certificate.tbsCertificate.serialNumber

        for (const crl of crls) {
            if (!crl.tbsCertList.revokedCertificates) {
                continue
            }

            for (const revokedCert of crl.tbsCertList.revokedCertificates) {
                // Compare serial numbers by converting to hex strings for reliable comparison
                const revokedSerialHex = this.serialNumberToHex(
                    revokedCert.userCertificate,
                )
                const certSerialHex = serialNumber.toHexString()

                if (revokedSerialHex === certSerialHex) {
                    // Extract revocation reason if available from extensions
                    let reason: number | undefined
                    let details = 'Certificate found in CRL'

                    if (revokedCert.crlEntryExtensions) {
                        for (const ext of revokedCert.crlEntryExtensions) {
                            // CRL Reason Code OID: 2.5.29.21
                            if (
                                ext.extnID.value ===
                                OIDs.EXTENSION.CRL_REASON_CODE
                            ) {
                                reason = ext.extnValue.parseAs(CRLReason).value
                                break
                            }
                        }
                    }

                    return {
                        isRevoked: true,
                        source: 'CRL',
                        reason,
                        revocationTime: revokedCert.revocationDate,
                        details,
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
     * Converts a serial number (number or string) to a consistent hex representation.
     */
    private serialNumberToHex(serialNumber: number | string): string {
        if (typeof serialNumber === 'number') {
            return serialNumber.toString(16).padStart(2, '0').toUpperCase()
        } else {
            // If it's already a hex string, normalize it
            return serialNumber.replace(/[^0-9A-Fa-f]/g, '').toUpperCase()
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

        // Basic check: subject equals issuer
        return (
            subject.equals(issuer) &&
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

            // Check if subject name matches issuer name
            if (candidateSubject.toString() === issuerName.toString()) {
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
        const certIssuer = certificate.tbsCertificate.issuer.toString()
        const issuerSubject = issuer.tbsCertificate.subject.toString()

        return certIssuer === issuerSubject
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
                if (!keyUsage.digitalSignature) {
                    // Digital Signature is required for CA certificates
                    return {
                        isValid: false,
                        message:
                            'CA certificate must have Digital Signature key usage',
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
     * Validates name constraints against a certificate.
     */
    private validateNameConstraints(
        certificate: Certificate,
        nameConstraints: NameConstraints,
    ): { isValid: boolean; message: string } {
        // Simplified name constraints validation
        // In a full implementation, this would parse the Subject Alternative Name extension
        // and check against the permitted/excluded subtrees

        const subject = certificate.tbsCertificate.subject

        const subjectAltNames = this.extractSubjectAltNames(certificate).map(
            (san) => san.toString(),
        )
        // For testing, we'll also check the common name from the subject
        const subjectCommonName = this.extractCommonName(certificate)

        // Check permitted subtrees
        if (
            nameConstraints.permittedSubtrees &&
            nameConstraints.permittedSubtrees.length > 0
        ) {
            const permitted =
                nameConstraints.permittedSubtrees.matches(subject) ||
                (subjectCommonName &&
                    nameConstraints.permittedSubtrees.matches(
                        subjectCommonName,
                    )) ||
                subjectAltNames.some((san) =>
                    nameConstraints.permittedSubtrees?.matches(san),
                )

            if (!permitted) {
                return {
                    isValid: false,
                    message: `Certificate name '${subjectCommonName || subject}' not in permitted subtrees`,
                }
            }
        }

        // Check excluded subtrees
        if (
            nameConstraints.excludedSubtrees &&
            nameConstraints.excludedSubtrees.length > 0
        ) {
            if (
                nameConstraints.excludedSubtrees.matches(subject) ||
                (subjectCommonName &&
                    nameConstraints.excludedSubtrees.matches(subjectCommonName))
            ) {
                return {
                    isValid: false,
                    message: `Certificate name '${subjectCommonName || subject}' matches excluded subtree`,
                }
            }
        }

        return {
            isValid: true,
            message: 'Name constraints validated successfully',
        }
    }

    private extractSubjectAltNames(certificate: Certificate): SubjectAltName[] {
        const subjectAltNames: SubjectAltName[] = []
        const extensions = certificate.tbsCertificate.extensions
        if (!extensions) return []

        for (const ext of extensions) {
            // Subject Alternative Name OID:
            if (ext.extnID.value === OIDs.EXTENSION.SUBJECT_ALT_NAME) {
                subjectAltNames.push(ext.extnValue.parseAs(SubjectAltName))
            }
        }

        return subjectAltNames
    }

    /**
     * Extracts the common name (CN) from a certificate's subject.
     */
    private extractCommonName(certificate: Certificate): string | undefined {
        const subject = certificate.tbsCertificate.subject

        if (subject && Array.isArray(subject)) {
            for (const rdn of subject) {
                for (const atv of rdn) {
                    if (atv && atv.type && atv.type.value === OIDs.DN.CN) {
                        return atv.value.asString()
                    }
                }
            }
        }

        // Fallback: extract from string representation
        const subjectStr = subject.toString()
        const cnMatch = subjectStr.match(/CN=([^,\]]+)/)
        return cnMatch ? cnMatch[1].trim() : undefined
    }

    /**
     * Validates certificate policies.
     */
    private validatePolicies(
        chain: CertificateChain,
        requiredPolicies?: string[],
    ): PolicyValidationResult {
        const validPolicies: string[] = []
        const violations: string[] = []

        // Extract policies from each certificate in the chain
        for (const certificate of chain.certificates) {
            const policies = this.extractCertificatePolicies(certificate)
            validPolicies.push(...policies)
        }

        // Check required policies if specified
        if (requiredPolicies && requiredPolicies.length > 0) {
            for (const requiredPolicy of requiredPolicies) {
                if (!validPolicies.includes(requiredPolicy)) {
                    violations.push(
                        `Required policy not found: ${requiredPolicy}`,
                    )
                }
            }
        }

        return {
            isValid: violations.length === 0,
            validPolicies: [...new Set(validPolicies)], // Remove duplicates
            violations,
        }
    }

    /**
     * Extracts certificate policy OIDs from a certificate.
     */
    private extractCertificatePolicies(certificate: Certificate): string[] {
        const policies: string[] = []
        const extensions = certificate.tbsCertificate.extensions

        if (!extensions) return policies

        for (const ext of extensions) {
            // Certificate Policies OID: 2.5.29.32
            if (ext.extnID.value === '2.5.29.32') {
                // Simplified policy extraction
                // In reality, this would parse the PolicyInformation structure
                // For now, we'll just return the anyPolicy OID as a placeholder
                policies.push('2.5.29.32.0') // anyPolicy
            }
        }

        return policies
    }
}
