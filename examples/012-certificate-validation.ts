// Certificate chain building and validation

import { Certificate } from 'pki-lite/x509/Certificate.js'
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'

// For this example, you would typically load real certificates
// Here we show how to use the validator with placeholder certificates

console.log('=== Certificate Chain Validation Example ===\n')

// Example 1: Load certificates from PEM strings
const rootCertPem = `-----BEGIN CERTIFICATE-----
{your root CA certificate here}
-----END CERTIFICATE-----`

const intermediateCertPem = `-----BEGIN CERTIFICATE-----
{your intermediate CA certificate here}
-----END CERTIFICATE-----`

const endEntityCertPem = `-----BEGIN CERTIFICATE-----
{your end-entity certificate here}
-----END CERTIFICATE-----`

// Parse the certificates
const rootCert = Certificate.fromPem(rootCertPem)
const intermediateCert = Certificate.fromPem(intermediateCertPem)
const endEntityCert = Certificate.fromPem(endEntityCertPem)

console.log('Loaded certificates:')
console.log('  Root CA:', rootCert.tbsCertificate.subject.toString())
console.log(
    '  Intermediate CA:',
    intermediateCert.tbsCertificate.subject.toString(),
)
console.log('  End Entity:', endEntityCert.tbsCertificate.subject.toString())

console.log('\n=== Validation 1: Basic Certificate Validation ===')
const validator = new CertificateValidator()

// Validate just the end-entity certificate (without chain validation)
const basicValidation = await validator.validate(endEntityCert, {
    checkSignature: false, // Don't check signature without issuer
})

console.log('Validation Status:', basicValidation.status)
console.log('Is Valid:', basicValidation.isValid)
console.log('Messages:', basicValidation.messages.join(', '))
console.log('Validated At:', basicValidation.validatedAt.toISOString())

console.log('\n=== Validation 2: Certificate Chain Validation ===')

// Validate the full certificate chain
const chainValidation = await validator.validate(endEntityCert, {
    validateChain: true,
    checkSignature: true,
    enforceCAConstraints: true,
    trustAnchors: [
        {
            certificate: rootCert,
        },
    ],
    otherCertificates: [intermediateCert], // Intermediate certificates for chain building
})

console.log('Chain Validation Status:', chainValidation.status)
console.log('Is Valid:', chainValidation.isValid)
console.log('Messages:', chainValidation.messages.join(', '))

if (chainValidation.chain) {
    console.log('\nCertificate Chain:')
    console.log('  Is Complete:', chainValidation.chain.isComplete)
    console.log('  Chain Length:', chainValidation.chain.certificates.length)
    chainValidation.chain.certificates.forEach((cert, index) => {
        console.log(`  [${index}] ${cert.tbsCertificate.subject.toString()}`)
    })
}

console.log('\nDiagnostics:')
console.log(
    '  Steps Performed:',
    chainValidation.diagnostics.stepsPerformed.length,
)
chainValidation.diagnostics.stepsPerformed.forEach((step) => {
    console.log(`    - ${step}`)
})

if (chainValidation.diagnostics.warnings.length > 0) {
    console.log('  Warnings:', chainValidation.diagnostics.warnings.length)
    chainValidation.diagnostics.warnings.forEach((warning) => {
        console.log(`    ! ${warning}`)
    })
}

console.log('\n=== Validation 3: With Custom Validation Time ===')

// Validate with a specific date (useful for checking historical validity)
const historicalDate = new Date('2023-06-01T00:00:00Z')
const historicalValidation = await validator.validate(endEntityCert, {
    validationTime: historicalDate,
    timeTolerance: 300000, // 5 minutes tolerance in milliseconds
})

console.log('Historical Validation Status:', historicalValidation.status)
console.log('Is Valid:', historicalValidation.isValid)
console.log('Validation Time:', historicalDate.toISOString())

console.log('\n=== Validation 4: With Revocation Checking (CRL) ===')

// If you have CRLs available
const crl = await endEntityCert.requestCrl()
if (crl) {
    const crlValidation = await validator.validate(
        endEntityCert,
        {
            checkCRL: true,
        },
        {
            crls: [crl],
            issuerCertificate: intermediateCert,
        },
    )

    console.log('CRL Validation Status:', crlValidation.status)
    console.log('Is Valid:', crlValidation.isValid)
    console.log('Revocation Status:')
    console.log('  Is Revoked:', crlValidation.revocationStatus.isRevoked)
    console.log('  Source:', crlValidation.revocationStatus.source)
    if (crlValidation.revocationStatus.reason !== undefined) {
        console.log('  Reason:', crlValidation.revocationStatus.reason)
    }
} else {
    console.log('No CRL available for this certificate')
}

console.log('\n=== Validation 5: With Name Constraints ===')

// Validate with name constraints (if the CA has name constraints)
const nameConstraintsValidation = await validator.validate(endEntityCert, {
    validateChain: true,
    validateNameConstraints: true,
    trustAnchors: [
        {
            certificate: rootCert,
            // nameConstraints: customNameConstraints, // Add custom constraints if needed
        },
    ],
    otherCertificates: [intermediateCert],
})

console.log(
    'Name Constraints Validation Status:',
    nameConstraintsValidation.status,
)
console.log('Is Valid:', nameConstraintsValidation.isValid)

console.log('\n=== Validation 6: Policy Validation ===')

// Validate with required policies
const policyValidation = await validator.validate(endEntityCert, {
    validateChain: true,
    validatePolicies: true,
    requiredPolicies: ['1.3.6.1.4.1.99999.1.2.3'], // Example policy OID
    trustAnchors: [
        {
            certificate: rootCert,
        },
    ],
    otherCertificates: [intermediateCert],
})

console.log('Policy Validation Status:', policyValidation.status)
console.log('Is Valid:', policyValidation.isValid)
if (policyValidation.policyResult) {
    console.log('Policy Result:')
    console.log('  Is Valid:', policyValidation.policyResult.isValid)
    console.log(
        '  Valid Policies:',
        policyValidation.policyResult.validPolicies,
    )
    console.log('  Violations:', policyValidation.policyResult.violations)
}

console.log('\n=== Certificate Information ===')

// Extract useful information from a certificate
console.log('\nEnd Entity Certificate Details:')
console.log('  Version:', endEntityCert.tbsCertificate.version + 1) // Version is 0-indexed
console.log(
    '  Serial Number:',
    endEntityCert.tbsCertificate.serialNumber.toString(),
)
console.log('  Subject:', endEntityCert.tbsCertificate.subject.toString())
console.log('  Issuer:', endEntityCert.tbsCertificate.issuer.toString())
console.log(
    '  Not Before:',
    endEntityCert.tbsCertificate.validity.notBefore.toISOString(),
)
console.log(
    '  Not After:',
    endEntityCert.tbsCertificate.validity.notAfter.toISOString(),
)
console.log(
    '  Signature Algorithm:',
    endEntityCert.signatureAlgorithm.algorithm.toString(),
)

if (endEntityCert.tbsCertificate.extensions) {
    console.log('  Extensions:', endEntityCert.tbsCertificate.extensions.length)
    endEntityCert.tbsCertificate.extensions.forEach((ext) => {
        console.log(`    - ${ext.extnID.value} (Critical: ${ext.critical})`)
    })
}
