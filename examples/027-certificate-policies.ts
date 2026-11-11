// Certificate policies: requiring, mapping and constraining policies along a chain

import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Certificate Policies Example ===\n')

// Policy OIDs: what the root's domain calls "high assurance", and what the
// intermediate CA's own domain calls it
const ROOT_HIGH_ASSURANCE = '1.3.6.1.4.1.99999.1.1'
const SUBCA_HIGH_ASSURANCE = '1.3.6.1.4.1.99999.2.1'
const LOW_ASSURANCE = '1.3.6.1.4.1.99999.1.9'

// The CAs sign with RSA (the builder's default signature algorithm)
const [rootKeys, caKeys, leafKeys] = await Promise.all([
    KeyGen.generateRsaPair({ keySize: 2048 }),
    KeyGen.generateRsaPair({ keySize: 2048 }),
    KeyGen.generateEcPair({ namedCurve: 'P-256' }),
])

const root = await Certificate.builder()
    .setSubject('CN=Policy Root')
    .setPublicKey(rootKeys.publicKey)
    .setPrivateKey(rootKeys.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .selfSign()

// The intermediate CA asserts the root's policy, says its own domain's OID means the
// same (a policy mapping), and requires every certificate below it to carry an
// acceptable policy (requireExplicitPolicy: 0)
const intermediate = await Certificate.builder()
    .setSubject('CN=Policy Sub CA')
    .setIssuer(root)
    .setPublicKey(caKeys.publicKey)
    .setIssuerPrivateKey(rootKeys.privateKey)
    .setValidityDays(1825)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .addCertificatePolicies(ROOT_HIGH_ASSURANCE)
    .addPolicyMappings({
        issuerDomainPolicy: ROOT_HIGH_ASSURANCE,
        subjectDomainPolicy: SUBCA_HIGH_ASSURANCE,
    })
    .addPolicyConstraints({ requireExplicitPolicy: 0 })
    .sign()

async function leaf(...policies: string[]) {
    const builder = Certificate.builder()
        .setSubject('CN=server.example.com')
        .setIssuer(intermediate)
        .setPublicKey(leafKeys.publicKey)
        .setIssuerPrivateKey(caKeys.privateKey)
        .setValidityDays(90)
        .generateSerialNumber()
        .addBasicConstraints(false)
    if (policies.length > 0) builder.addCertificatePolicies(...policies)
    return builder.sign()
}

const validator = new CertificateValidator()
const validate = (certificate: Certificate, options: object = {}) =>
    validator.validate(certificate, {
        validateChain: true,
        trustAnchors: [{ certificate: root }],
        otherCertificates: [intermediate],
        ...options,
    })

const cases: [string, Certificate, object][] = [
    // the leaf uses the sub CA's OID, which the mapping ties to the root's policy
    ['mapped high-assurance leaf', await leaf(SUBCA_HIGH_ASSURANCE), {}],
    // the CA's policy constraints demand a policy, and this leaf has none
    ['leaf without policies', await leaf(), {}],
    // a policy the CA never asserted is not valid for the path
    ['low-assurance leaf', await leaf(LOW_ASSURANCE), {}],
    // the relying party only accepts the root's high-assurance policy
    [
        'mapped leaf, only high assurance accepted',
        await leaf(SUBCA_HIGH_ASSURANCE),
        { initialPolicySet: [ROOT_HIGH_ASSURANCE] },
    ],
    // ...but refuses policy mapping altogether
    [
        'mapped leaf, mappings not allowed',
        await leaf(SUBCA_HIGH_ASSURANCE),
        { initialPolicyMappingInhibit: true },
    ],
]

for (const [label, certificate, options] of cases) {
    const result = await validate(certificate, options)
    console.log(`${label.padEnd(42)} valid: ${result.isValid}`)
    if (result.isValid) {
        console.log(`    valid policies: ${result.policyResult?.validPolicies}`)
    } else {
        console.log(`    ${result.messages.join('; ')}`)
    }
}
