// Reading certificate extensions

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { OIDs } from 'pki-lite/core/OIDs.js'
import { SubjectKeyIdentifier } from 'pki-lite/keys/SubjectKeyIdentifier.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { BasicConstraints } from 'pki-lite/x509/extensions/BasicConstraints.js'
import { ExtKeyUsage } from 'pki-lite/x509/extensions/ExtKeyUsage.js'
import { KeyUsage } from 'pki-lite/x509/extensions/KeyUsage.js'
import { GeneralName } from 'pki-lite/x509/GeneralName.js'

console.log('=== Certificate Extensions Example ===\n')

// A certificate with a typical set of extensions (any certificate would do)
const keyPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
const certificate = await Certificate.builder()
    .setSubject('CN=www.example.com, O=Example Org, C=GB')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setAlgorithm({
        type: 'ECDSA',
        params: { namedCurve: 'P-256', hash: 'SHA-256' },
    })
    .setValidityDays(90)
    .generateSerialNumber()
    .addBasicConstraints(false)
    .addKeyUsage({ digitalSignature: true })
    .addExtendedKeyUsage({ serverAuth: true, clientAuth: true })
    .addSubjectAltName(
        'www.example.com',
        'example.com',
        new GeneralName.rfc822Name({ value: 'admin@example.com' }),
        new GeneralName.iPAddress({ bytes: new Uint8Array([192, 0, 2, 1]) }),
    )
    .addSubjectKeyIdentifier(crypto.getRandomValues(new Uint8Array(20)))
    .selfSign()

// Every extension, with its OID and whether it is critical
console.log('Extensions present:')
for (const extension of certificate.tbsCertificate.extensions ?? []) {
    console.log(
        `  ${extension.extnID.friendlyName} (${extension.extnID})`,
        extension.critical ? '[critical]' : '',
    )
}

// Look one up by OID and parse its value as the matching class
const basicConstraints = certificate
    .getExtensionByOid(OIDs.EXTENSION.BASIC_CONSTRAINTS)
    ?.extnValue.parseAs(BasicConstraints)
console.log('\nIs a CA:', basicConstraints?.cA)

const keyUsage = certificate
    .getExtensionByOid(OIDs.EXTENSION.KEY_USAGE)
    ?.extnValue.parseAs(KeyUsage)
console.log(
    'Key usage:',
    Object.entries(keyUsage ?? {})
        .filter(([, set]) => set === true)
        .map(([name]) => name),
)

const extKeyUsage = certificate
    .getExtensionByOid(OIDs.EXTENSION.EXTENDED_KEY_USAGE)
    ?.extnValue.parseAs(ExtKeyUsage)
console.log(
    'Extended key usage:',
    [...(extKeyUsage ?? [])].map((oid) => oid.friendlyName),
)

const keyIdentifier = certificate
    .getExtensionByOid(OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER)
    ?.extnValue.parseAs(SubjectKeyIdentifier)
console.log('Subject key identifier:', keyIdentifier?.toHumanString())

// Subject alternative names: each entry is a typed GeneralName
console.log('\nSubject alternative names:')
for (const alternativeNames of certificate.getSubjectAltNames()) {
    for (const name of alternativeNames) {
        const value =
            name instanceof GeneralName.iPAddress
                ? [...name.bytes].join('.') // an IPv4 address is 4 raw bytes
                : name.toString()
        console.log(`  ${name.constructor.name}: ${value}`)
    }
}
console.log('Common name:', certificate.getCommonName())
