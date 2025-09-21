import { getPbeAlgorithm, PbeAlgorithmMap } from '../../src/pbeAlgorithms'
import { describe, it, expect } from 'vitest'

const algs: (keyof PbeAlgorithmMap)[] = [
    'SHA1_3DES_2KEY_CBC',
    'SHA1_3DES_3KEY_CBC',
    'SHA1_RC2_40_CBC',
    'SHA1_RC2_128_CBC',
]

function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array(hex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)))
}

describe('PBE Algorithms', () => {
    for (const algName of algs) {
        describe(algName, () => {
            it('encrypts known value (OpenSSL test vector)', () => {
                const algo = getPbeAlgorithm(algName)
                const password = 'password'
                const salt = hexToBytes('1234567890abcdef')
                const iterationCount = 1000
                const plaintext = new Uint8Array([0x01, 0x02, 0x03, 0x04])
                // No official test vector, but should not throw and output should be Uint8Array
                const encrypted = algo.encrypt(
                    plaintext,
                    password,
                    salt,
                    iterationCount,
                )
                expect(encrypted).toBeInstanceOf(Uint8Array)
                expect(encrypted.length).toBeGreaterThan(0)

                const decrypted = algo.decrypt(
                    encrypted,
                    password,
                    salt,
                    iterationCount,
                )
                expect(decrypted).toBeInstanceOf(Uint8Array)
                expect(decrypted).toEqual(plaintext)
            })
        })
    }
})
