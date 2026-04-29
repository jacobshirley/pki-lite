// Building OCSP responses using the OCSPResponse builder

import { OCSPResponse } from 'pki-lite/ocsp/OCSPResponse.js'
import { CertID } from 'pki-lite/ocsp/CertID.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { OCSPResponseStatus } from 'pki-lite/ocsp/OCSPResponseStatus.js'

console.log('=== OCSP Response Builder Examples ===\n')

// Setup: Create CA and certificates
console.log('Setting up CA and certificates...')
const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const caCert = await Certificate.builder()
    .setSubject('CN=OCSP CA, O=Example Org, C=US')
    .setPublicKey(caKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true, 2)
    .addKeyUsage({
        keyCertSign: true,
        cRLSign: true,
    })
    .selfSign()

// Create an OCSP responder key
const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const responderCert = await Certificate.builder()
    .setSubject('CN=OCSP Responder, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(responderKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .addKeyUsage({
        digitalSignature: true,
    })
    .addExtendedKeyUsage({
        ocspSigning: true,
    })
    .build()

// Create some end-entity certificates
const cert1KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const cert1 = await Certificate.builder()
    .setSubject('CN=User 1, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(cert1KeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .setSerialNumber(2001)
    .build()

const cert2KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const cert2 = await Certificate.builder()
    .setSubject('CN=User 2, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(cert2KeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .setSerialNumber(2002)
    .build()

console.log('✓ Setup complete\n')

// Example 1: Basic OCSP response with good status (using Certificate directly)
console.log('=== Example 1: Basic OCSP Response (Good Status) ===')

const goodResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert1, 'good') // Pass issuer and certificate!
    .build()

console.log('✓ OCSP response created with good status')
console.log('  Response Status:', goodResponse.responseStatus.value)
const basicResp1 = goodResponse.getBasicOCSPResponse()
console.log('  Responses:', basicResp1.tbsResponseData.responses.length)
console.log(
    '  Certificate Status:',
    basicResp1.tbsResponseData.responses[0].certStatus.status,
)
console.log('  Response size:', goodResponse.toDer().length, 'bytes\n')

// Example 2: OCSP response with revoked status
console.log('=== Example 2: OCSP Response with Revoked Status ===')
const revocationDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // 7 days ago

const revokedResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert2, 'revoked', {
        revocationTime: revocationDate,
        revocationReason: 0, // unspecified reason
    })
    .build()

console.log('✓ OCSP response created with revoked status')
const basicResp2 = revokedResponse.getBasicOCSPResponse()
console.log(
    '  Certificate Status:',
    basicResp2.tbsResponseData.responses[0].certStatus.status,
)
console.log(
    '  Revocation Time:',
    basicResp2.tbsResponseData.responses[0].certStatus.revocationTime,
)
console.log()

// Example 3: Multiple certificate responses in one OCSP response
console.log('=== Example 3: Multiple Certificate Responses ===')
const multiResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert1, 'good') // Add multiple responses!
    .addResponse(caCert, cert2, 'revoked', {
        revocationTime: revocationDate,
        revocationReason: 0,
    })
    .build()

console.log('✓ OCSP response with multiple certificates created')
const basicResp3 = multiResponse.getBasicOCSPResponse()
console.log('  Total responses:', basicResp3.tbsResponseData.responses.length)
console.log(
    '  Response 1 status:',
    basicResp3.tbsResponseData.responses[0].certStatus.status,
)
console.log(
    '  Response 2 status:',
    basicResp3.tbsResponseData.responses[1].certStatus.status,
)
console.log()

// Example 4: OCSP response with custom validity period
console.log('=== Example 4: Custom Validity Period ===')
const now = new Date()
const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000)
const nextWeek = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000)

const customValidityResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .setProducedAt(now)
    .addResponse(caCert, cert1, 'good', {
        thisUpdate: tomorrow,
        nextUpdate: nextWeek,
    })
    .build()

console.log('✓ OCSP response with custom validity created')
const basicResp4 = customValidityResponse.getBasicOCSPResponse()
console.log('  Produced At:', basicResp4.tbsResponseData.producedAt)
console.log(
    '  This Update:',
    basicResp4.tbsResponseData.responses[0].thisUpdate.time,
)
console.log(
    '  Next Update:',
    basicResp4.tbsResponseData.responses[0].nextUpdate?.time,
)
console.log()

// Example 5: OCSP response with responder certificate included
console.log('=== Example 5: Including Responder Certificate ===')
const withCertResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert1, 'good')
    .addCertificate(responderCert) // Include responder cert for validation
    .build()

console.log('✓ OCSP response with responder certificate created')
const basicResp5 = withCertResponse.getBasicOCSPResponse()
console.log('  Included certificates:', basicResp5.certs?.length || 0)
if (basicResp5.certs && basicResp5.certs.length > 0) {
    console.log(
        '  Responder cert subject:',
        basicResp5.certs[0].tbsCertificate.subject.toString(),
    )
}
console.log()

// Example 6: Error response (no signature required)
console.log('=== Example 6: Error Response ===')
const errorResponse = await OCSPResponse.builder()
    .setResponseStatus(OCSPResponseStatus.malformedRequest)
    .build()

console.log('✓ Error response created')
console.log('  Response Status:', errorResponse.responseStatus.value)
console.log('  Has response bytes:', !!errorResponse.responseBytes)
console.log()

// Example 7: Using OCSPResponse.forCertificate() shorthand
console.log('=== Example 7: Using forCertificate() Shorthand ===')
const shorthandResponse = await OCSPResponse.forCertificate({
    issuerCertificate: caCert,
    subjectCertificate: cert1,
    privateKey: responderKeyPair.privateKey,
    responderID: responderCert.tbsCertificate.subject,
})

console.log('✓ OCSP response created using shorthand method')
console.log('  Response Status:', shorthandResponse.responseStatus.value)
console.log('  Response size:', shorthandResponse.toDer().length, 'bytes')
console.log()

// Example 8: Export and parse OCSP response
console.log('=== Example 8: Export and Parse OCSP Response ===')
const der = goodResponse.toDer()
console.log('✓ OCSP response exported to DER')
console.log('  DER size:', der.length, 'bytes')

const parsed = OCSPResponse.fromDer(der)
console.log('✓ OCSP response parsed from DER')
console.log(
    '  Status matches:',
    parsed.responseStatus.value === goodResponse.responseStatus.value,
)
