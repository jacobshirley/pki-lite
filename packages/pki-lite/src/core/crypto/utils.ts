import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { getCryptoProvider } from './provider.js'
import type { HashAlgorithm } from './types.js'

/**
 * PKCS#12 password-based key derivation (RFC 7292 Appendix B.2).
 * @param password Password as BMPString (UTF-16BE) with NUL terminator
 * @param salt Salt bytes
 * @param id 1 = encryption key, 2 = IV, 3 = MAC key
 * @param iterations Iteration count
 * @param n Number of bytes to produce
 * @param hash Hash algorithm
 */

export async function pkcs12Derive(
    password: Uint8Array<ArrayBuffer>,
    salt: Uint8Array<ArrayBuffer>,
    id: 1 | 2 | 3,
    iterations: number,
    n: number,
    hash: HashAlgorithm,
): Promise<Uint8Array<ArrayBuffer>> {
    const digestAlgorithm = AlgorithmIdentifier.digestAlgorithm(hash)
    const u = digestAlgorithm.getOutputBytes()
    const v = digestAlgorithm.getBlockBytes()

    // Step 1: D = ID byte repeated v times
    const D = new Uint8Array(v).fill(id)

    // Step 2: S = salt extended to ceil(s/v) * v
    const sLen = salt.length === 0 ? 0 : Math.ceil(salt.length / v) * v
    const S = new Uint8Array(sLen)
    for (let i = 0; i < sLen; i++) S[i] = salt[i % salt.length]

    // Step 3: P = password extended to ceil(p/v) * v
    const pLen = password.length === 0 ? 0 : Math.ceil(password.length / v) * v
    const P = new Uint8Array(pLen)
    for (let i = 0; i < pLen; i++) P[i] = password[i % password.length]

    // Step 4: I = S || P
    let I = new Uint8Array(sLen + pLen)
    I.set(S)
    I.set(P, sLen)

    // Step 5: For each block i = 1..c, c = ceil(n/u)
    const c = Math.ceil(n / u)
    const result = new Uint8Array(c * u)

    const crypto = getCryptoProvider()

    for (let i = 0; i < c; i++) {
        // a) A_i = H^iterations(D || I)
        const di = new Uint8Array(D.length + I.length)
        di.set(D)
        di.set(I, D.length)
        let Ai = await crypto.digest(di, hash)
        for (let j = 1; j < iterations; j++) {
            Ai = await crypto.digest(Ai, hash)
        }
        result.set(Ai, i * u)

        if (i + 1 === c) break

        // b) B = Ai concatenated to fill v bytes
        const B = new Uint8Array(v)
        for (let j = 0; j < v; j++) B[j] = Ai[j % u]

        // c) For each v-byte block I_j of I: I_j = (I_j + B + 1) mod 2^(v*8)
        const numBlocks = I.length / v
        const newI = new Uint8Array(I.length)
        for (let j = 0; j < numBlocks; j++) {
            let carry = 1n
            for (let k = v - 1; k >= 0; k--) {
                const sum = BigInt(I[j * v + k]) + BigInt(B[k]) + carry
                newI[j * v + k] = Number(sum & 0xffn)
                carry = sum >> 8n
            }
        }
        I = newI
    }

    return result.slice(0, n)
}
