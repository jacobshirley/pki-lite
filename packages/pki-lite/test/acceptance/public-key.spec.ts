import { test, expect, describe } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { ecP521SigningKeys } from '../../test-fixtures/signing-keys/ec-p521/index.js'
import { SubjectPublicKeyInfo } from '../../src/keys/SubjectPublicKeyInfo.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { RSAPublicKey } from '../../src/keys/RSAPublicKey.js'
import { ECPublicKey } from '../../src/keys/ECPublicKey.js'

describe('SubjectPublicKeyInfo', () => {
    test('RSA Public Key Parsing', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const key: SubjectPublicKeyInfo =
            cert.tbsCertificate.subjectPublicKeyInfo
        const rsa = key.getPublicKey()

        expect(rsa).toBeInstanceOf(RSAPublicKey)
    })

    test('ECDSA Public Key Parsing', async () => {
        const cert = Certificate.fromPem(ecP521SigningKeys.certPem)
        const key: SubjectPublicKeyInfo =
            cert.tbsCertificate.subjectPublicKeyInfo
        const ecdsa = key.getPublicKey()

        expect(ecdsa).toBeInstanceOf(ECPublicKey)
    })
})
