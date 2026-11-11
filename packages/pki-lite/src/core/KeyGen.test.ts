import { describe, expect, it } from 'vitest'
import { KeyGen } from './KeyGen.js'
import { OIDs } from './OIDs.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { WebCryptoProvider } from './crypto/WebCryptoProvider.js'

// Bits in the RSA modulus, read from the RSAPublicKey in the SubjectPublicKeyInfo
function modulusBits(publicKey: {
    getRsaPublicKey(): { modulus: Uint8Array }
}): number {
    const bytes = publicKey.getRsaPublicKey().modulus
    // a leading 00 only keeps the INTEGER positive
    return (bytes[0] === 0 ? bytes.length - 1 : bytes.length) * 8
}

describe('KeyGen honours the requested key size and curve', () => {
    it('generates an RSA key of the requested size', async () => {
        const { publicKey } = await KeyGen.generateRsaPair({ keySize: 3072 })
        expect(modulusBits(publicKey)).toBe(3072)
    })

    it('defaults to 2048-bit RSA', async () => {
        const { publicKey } = await KeyGen.generateRsaPair()
        expect(modulusBits(publicKey)).toBe(2048)
    })

    for (const [curve, oid] of [
        ['P-256', OIDs.CURVES.SECP256R1],
        ['P-384', OIDs.CURVES.SECP384R1],
        ['P-521', OIDs.CURVES.SECP521R1],
    ] as const) {
        it(`generates an EC key on ${curve}`, async () => {
            const { publicKey } = await KeyGen.generateEcPair({
                namedCurve: curve,
            })
            const parameters =
                publicKey.algorithm.parameters?.parseAs(ObjectIdentifier)
            expect(parameters?.value).toBe(oid)
        })
    }

    it('still accepts the flat option form on the provider', async () => {
        const provider = new WebCryptoProvider()
        const keys = await provider.generateKeyPair({
            algorithm: 'EC',
            namedCurve: 'P-384',
        })
        // a P-384 SubjectPublicKeyInfo is larger than a P-256 one (120 vs 91 bytes)
        expect(keys.publicKey.length).toBe(120)
    })

    it('accepts a numeric public exponent', async () => {
        const provider = new WebCryptoProvider()
        const keys = await provider.generateKeyPair({
            algorithm: 'RSA',
            params: { keySize: 2048, publicExponent: 3 },
        })
        expect(keys.publicKey.length).toBeGreaterThan(200)
    })
})
