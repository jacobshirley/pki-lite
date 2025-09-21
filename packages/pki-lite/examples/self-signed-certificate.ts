import { PrivateKeyInfo } from '../src/keys/PrivateKeyInfo.js'
import { Certificate } from '../src/x509/Certificate.js'
import { rsaSigningKeys } from '../test-fixtures/signing-keys/rsa-2048/index.js'

const selfSigned = await Certificate.createSelfSignedCertificate({
    subject: 'CN=Test Self-Signed Certificate, O=My Organization, C=US',
    validity: {
        notBefore: new Date('2023-01-01T00:00:00Z'),
        notAfter: new Date('2024-01-01T00:00:00Z'),
    },
    privateKeyInfo: PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem),
    subjectPublicKeyInfo: Certificate.fromPem(rsaSigningKeys.certPem)
        .tbsCertificate.subjectPublicKeyInfo,
})

console.log('Self-Signed Certificate PEM:', selfSigned.toPem())
