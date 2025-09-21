import { EnvelopedData } from '../../src/pkcs7/EnvelopedData.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { describe, test, expect } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { opensslCmsDecrypt } from '../../test-fixtures/openSsl.js'
import { PrivateKeyInfo } from '../../src/keys/PrivateKeyInfo.js'

describe('EnvelopedData', () => {
    test('EnvelopedDataBuilder should build valid EnvelopedData', async () => {
        const data = 'Hello World'

        const envelopedData = (
            await EnvelopedData.builder()
                .setData(data)
                .addRecipient({
                    certificate: Certificate.fromPem(rsaSigningKeys.certPem),
                })
                .build()
        ).toCms()

        const der = envelopedData.toDer()

        const parsed = EnvelopedData.fromCms(envelopedData)
        const decrypted = await parsed.decrypt(
            PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem),
        )

        expect(new TextDecoder().decode(decrypted)).toEqual(data)
    })
})
