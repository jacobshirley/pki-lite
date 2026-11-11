// Restricting a CA with name constraints

import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { Extension } from 'pki-lite/x509/Extension.js'
import {
    GeneralSubtree,
    NameConstraints,
} from 'pki-lite/x509/extensions/NameConstraints.js'
import { dNSName } from 'pki-lite/x509/GeneralName.js'

console.log('=== Name Constraints Example ===\n')

// A CA that may only issue for example.com and its subdomains, except secret.example.com
const nameConstraints = new NameConstraints({
    permittedSubtrees: [
        new GeneralSubtree({ base: new dNSName({ value: 'example.com' }) }),
    ],
    excludedSubtrees: [
        new GeneralSubtree({
            base: new dNSName({ value: 'secret.example.com' }),
        }),
    ],
})

const caKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const caCertificate = await Certificate.builder()
    .setSubject('CN=Constrained CA, O=Example Org')
    .setPublicKey(caKeys.publicKey)
    .setPrivateKey(caKeys.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .addExtension(
        new Extension({
            extnID: '2.5.29.30', // id-ce-nameConstraints
            critical: true,
            extnValue: nameConstraints,
        }),
    )
    .selfSign()
console.log('Created CA with name constraints\n')

// The constraints can be read back from the certificate and checked directly
const constraints = caCertificate
    .getExtensionByOid('2.5.29.30')!
    .extnValue.parseAs(NameConstraints)
for (const name of ['www.example.com', 'www.evil.com', 'secret.example.com']) {
    const permitted = constraints.permittedSubtrees?.matches(name) ?? true
    const excluded = constraints.excludedSubtrees?.matches(name) ?? false
    console.log(
        `${name.padEnd(20)} permitted: ${permitted}, excluded: ${excluded}`,
    )
}

// Issue a certificate for each name and let the validator apply the constraints
console.log('\nValidating issued certificates:')
const validator = new CertificateValidator()
for (const host of ['www.example.com', 'www.evil.com', 'secret.example.com']) {
    const keys = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
    const certificate = await Certificate.builder()
        .setSubject(`CN=${host}`)
        .setIssuer(caCertificate)
        .setPublicKey(keys.publicKey)
        .setIssuerPrivateKey(caKeys.privateKey)
        .setValidityDays(30)
        .generateSerialNumber()
        .addBasicConstraints(false)
        .addSubjectAltName(host)
        .sign()

    const result = await validator.validate(certificate, {
        validateChain: true,
        validateNameConstraints: true,
        // Constraints are applied when given with the trust anchor. (The validator does not
        // yet read name constraints from the extensions of CAs inside the chain.)
        trustAnchors: [
            { certificate: caCertificate, nameConstraints: constraints },
        ],
    })
    console.log(`  ${host.padEnd(20)} valid: ${result.isValid}`)
    if (!result.isValid) {
        console.log(`    ${result.messages.join('; ')}`)
    }
}
