import { test, expect, describe } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { ecP521SigningKeys } from '../../test-fixtures/signing-keys/ec-p521/index.js'
import { PrivateKeyInfo } from '../../src/keys/PrivateKeyInfo.js'
import { RSAPrivateKey } from '../../src/keys/RSAPrivateKey.js'
import { ECPrivateKey } from '../../src/keys/ECPrivateKey.js'

describe('PrivateKeyInfo', () => {
    test('PrivateKeyInfo RSA PEM parsing', async () => {
        const key = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const rsa = key.getPrivateKey()

        expect(rsa).toBeInstanceOf(RSAPrivateKey)
    })

    test('PrivateKeyInfo EC PEM parsing', async () => {
        const key = PrivateKeyInfo.fromPem(ecP521SigningKeys.privateKeyPem)
        const ec = key.getPrivateKey()

        expect(ec).toBeInstanceOf(ECPrivateKey)
    })
})
