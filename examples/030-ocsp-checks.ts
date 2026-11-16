// Checking an OCSP response: verify, getResponse, isCurrent and revocation checking

import { Certificate } from 'pki-lite/x509/Certificate.js'
import { OCSPResponse } from 'pki-lite/ocsp/OCSPResponse.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'
import { OCSPRequest } from 'pki-lite/ocsp/OCSPRequest.js'
import { Extension } from 'pki-lite/x509/Extension.js'
import { OctetString } from 'pki-lite/asn1/OctetString.js'
import { OIDs } from 'pki-lite/core/OIDs.js'

// A CA, a delegated OCSP responder it authorises, and a certificate it issued
const caKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const ca = await Certificate.builder()
    .setSubject('CN=Example CA')
    .setPublicKey(caKeys.publicKey)
    .setPrivateKey(caKeys.privateKey)
    .setValidityDays(3650)
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .selfSign()

const responderKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const responder = await Certificate.builder()
    .setSubject('CN=Example OCSP Responder')
    .setPublicKey(responderKeys.publicKey)
    .setIssuer(ca)
    .setIssuerPrivateKey(caKeys.privateKey)
    .setValidityDays(365)
    .addExtendedKeyUsage({ ocspSigning: true })
    // id-pkix-ocsp-nocheck: clients need not check the responder's own revocation
    // status (without it, they must, e.g. with a CRL)
    .addExtension(
        new Extension({
            extnID: OIDs.PKIX.ID_PKIX_OCSP_NOCHECK,
            extnValue: new Uint8Array([0x05, 0x00]), // NULL
        }),
    )
    .sign()

const aliceKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const alice = await Certificate.builder()
    .setSubject('CN=Alice')
    .setPublicKey(aliceKeys.publicKey)
    .setIssuer(ca)
    .setIssuerPrivateKey(caKeys.privateKey)
    .setSerialNumber(1001)
    .setValidityDays(365)
    .sign()

// The responder answers for Alice's certificate
const response = OCSPResponse.fromDer(
    (
        await OCSPResponse.builder()
            .setPrivateKey(responderKeys.privateKey)
            .setResponderFromCertificate(responder)
            .addCertificate(responder)
            .addResponse(ca, alice, 'good', {
                nextUpdate: new Date(Date.now() + 24 * 60 * 60 * 1000),
            })
            .build()
    ).toDer(),
)

// 1. Is the response from the CA, or a responder it authorised (OCSPSigning)?
console.log('Successful:', response.isSuccessful)
console.log('Signed for the CA:', await response.verify(ca))

// 2. What does it say about Alice's certificate, and is it still current?
const single = await response.getResponse(alice, ca)
console.log('Status:', single?.certStatus.status)
console.log('Current:', single?.isCurrent())

// 3. Or let the validator do all of it: only a response that passes these checks counts
const validator = new CertificateValidator()
const result = await validator.validate(
    alice,
    { checkOCSP: true },
    { ocspResponses: [response], issuerCertificate: ca },
)
console.log('Validated:', result.status, `(${result.revocationStatus.source})`)

// A "good" signed by someone the CA never authorised is ignored
const forged = await OCSPResponse.builder()
    .setPrivateKey(aliceKeys.privateKey)
    .setResponderFromCertificate(alice)
    .addCertificate(alice)
    .addResponse(ca, alice, 'good')
    .build()
console.log('Forged response signed for the CA:', await forged.verify(ca))
const withForged = await validator.validate(
    alice,
    { checkOCSP: true },
    { ocspResponses: [forged], issuerCertificate: ca },
)
console.log(
    'Forged response used:',
    withForged.revocationStatus.source === 'OCSP',
)

// 4. A nonce (RFC 8954) ties a response to its request, so it cannot be replayed
const request = await OCSPRequest.builder()
    .addCertificate({ certificate: alice, issuerCertificate: ca })
    .addNonce()
    .build()
const echoing = await OCSPResponse.builder()
    .setPrivateKey(responderKeys.privateKey)
    .setResponderFromCertificate(responder)
    .addCertificate(responder)
    .addResponse(ca, alice, 'good')
    .addResponseExtension(
        new Extension({
            extnID: OIDs.PKIX.ID_PKIX_OCSP_NONCE,
            extnValue: new OctetString({ bytes: request.nonce! }),
        }),
    )
    .build()
console.log('Nonce echoed:', echoing.nonceMatches(request))
console.log("Another request's response:", response.nonceMatches(request)) // no nonce: undefined
