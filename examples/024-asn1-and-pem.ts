// Inspecting ASN.1, and converting between PEM and DER

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { ObjectIdentifier } from 'pki-lite/asn1/ObjectIdentifier.js'
import { derToAsn1 } from 'pki-lite/core/PkiBase.js'
import { ContentInfo } from 'pki-lite/pkcs7/ContentInfo.js'
import { SignedData } from 'pki-lite/pkcs7/SignedData.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== ASN.1 and PEM Example ===\n')

const keys = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
const certificate = await Certificate.builder()
    .setSubject('CN=ASN.1 Example')
    .setPublicKey(keys.publicKey)
    .setPrivateKey(keys.privateKey)
    .setAlgorithm({
        type: 'ECDSA',
        params: { namedCurve: 'P-256', hash: 'SHA-256' },
    })
    .setValidityDays(30)
    .generateSerialNumber()
    .selfSign()

// Every object converts to DER (binary) and PEM (base64 text) and back
const der = certificate.toDer()
const pem = certificate.toPem()
console.log('DER:', der.length, 'bytes, starts with', [...der.slice(0, 4)])
console.log('PEM:', pem.split('\n')[0], '...')
console.log(
    'Same certificate from DER and PEM:',
    Certificate.fromDer(der).equals(Certificate.fromPem(pem)),
)

// toString() prints the ASN.1 structure, handy for debugging
console.log('\nASN.1 of the subject public key:')
console.log(certificate.tbsCertificate.subjectPublicKeyInfo.toString())

// Parse bytes you know nothing about into a generic ASN.1 tree
const tree = derToAsn1(der)
console.log(
    '\nTop level:',
    tree.describe(),
    'with',
    tree.children.length,
    'elements',
)

// Unknown CMS data: look at the content type first, then parse as that type
const signed = await SignedData.builder()
    .setData(new TextEncoder().encode('data'))
    .addSigner({
        certificate,
        privateKeyInfo: keys.privateKey,
        encryptionAlgorithm: {
            type: 'ECDSA',
            params: { namedCurve: 'P-256', hash: 'SHA-256' },
        },
    })
    .build()
const unknown = ContentInfo.fromDer(signed.toCms().toDer())
console.log('\nCMS content type:', unknown.contentType.friendlyName)
if (unknown.contentType.is('1.2.840.113549.1.7.2')) {
    const parsed = unknown.parseContentAs(SignedData)
    console.log('Signers:', parsed.signerInfos.length)
    console.log('Embedded certificates:', parsed.certificates?.length)
}

// parseAs re-reads a value as another type, e.g. the curve OID in the key's parameters
const curve =
    certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters?.parseAs(
        ObjectIdentifier,
    )
console.log('\nCurve:', curve?.friendlyName, `(${curve})`)
