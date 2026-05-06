/**
 * Triple DES (3DES) implementation for legacy PKCS#12 support
 * Implements 3DES-CBC with 2-key and 3-key variants
 */

// DES S-boxes
const SBOX = [
    // S1
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14,
        2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12,
        9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    // S2
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15,
        2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8,
        12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14,
        9,
    ],
    // S3
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4,
        6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2,
        12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    // S4
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6,
        15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1,
        3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    // S5
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4,
        7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9,
        12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5,
        3,
    ],
    // S6
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7,
        12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4,
        10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    // S7
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4,
        9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15,
        6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    // S8
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10,
        3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10,
        13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]

// Permutation tables
const IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46,
    38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9,
    1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47,
    39, 31, 23, 15, 7,
]

const FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14,
    54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60,
    28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,
    9, 49, 17, 57, 25,
]

const E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15,
    16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28,
    29, 28, 29, 30, 31, 32, 1,
]

const P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14,
    32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]

const PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46,
    38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]

const PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27,
    20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

function permute(input: number[], table: number[]): number[] {
    return table.map((pos) => input[pos - 1])
}

function leftShift(bits: number[], n: number): number[] {
    return [...bits.slice(n), ...bits.slice(0, n)]
}

function xor(a: number[], b: number[]): number[] {
    return a.map((bit, i) => bit ^ b[i])
}

function bytesToBits(bytes: Uint8Array): number[] {
    const bits: number[] = []
    for (const byte of bytes) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1)
        }
    }
    return bits
}

function bitsToBytes(bits: number[]): Uint8Array {
    const bytes = new Uint8Array(bits.length / 8)
    for (let i = 0; i < bytes.length; i++) {
        let byte = 0
        for (let j = 0; j < 8; j++) {
            byte = (byte << 1) | bits[i * 8 + j]
        }
        bytes[i] = byte
    }
    return bytes
}

function generateSubkeys(key: Uint8Array): number[][] {
    const keyBits = bytesToBits(key)
    let permutedKey = permute(keyBits, PC1)

    let c = permutedKey.slice(0, 28)
    let d = permutedKey.slice(28, 56)

    const subkeys: number[][] = []
    for (const shift of SHIFTS) {
        c = leftShift(c, shift)
        d = leftShift(d, shift)
        const cd = [...c, ...d]
        subkeys.push(permute(cd, PC2))
    }

    return subkeys
}

function feistel(right: number[], subkey: number[]): number[] {
    const expanded = permute(right, E)
    const xored = xor(expanded, subkey)

    const sboxOutput: number[] = []
    for (let i = 0; i < 8; i++) {
        const block = xored.slice(i * 6, (i + 1) * 6)
        const row = (block[0] << 1) | block[5]
        const col =
            (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        const value = SBOX[i][row * 16 + col]
        for (let j = 3; j >= 0; j--) {
            sboxOutput.push((value >> j) & 1)
        }
    }

    return permute(sboxOutput, P)
}

function desEncryptBlock(block: Uint8Array, subkeys: number[][]): Uint8Array {
    let bits = bytesToBits(block)
    bits = permute(bits, IP)

    let left = bits.slice(0, 32)
    let right = bits.slice(32, 64)

    for (const subkey of subkeys) {
        const temp = right
        const fResult = feistel(right, subkey)
        right = xor(left, fResult)
        left = temp
    }

    const combined = [...right, ...left]
    const finalBits = permute(combined, FP)
    return bitsToBytes(finalBits)
}

function desDecryptBlock(block: Uint8Array, subkeys: number[][]): Uint8Array {
    return desEncryptBlock(block, [...subkeys].reverse())
}

/**
 * 3DES-CBC encryption (2-key or 3-key)
 */
export function tripleDesEncrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
): Uint8Array<ArrayBuffer> {
    // Pad to 8-byte blocks
    const blockSize = 8
    const paddingLength =
        blockSize - (plaintext.length % blockSize) || blockSize
    const padded = new Uint8Array(plaintext.length + paddingLength)
    padded.set(plaintext)
    for (let i = plaintext.length; i < padded.length; i++) {
        padded[i] = paddingLength
    }

    // Split key into K1, K2, K3
    const k1 = key.slice(0, 8)
    const k2 = key.slice(8, 16)
    const k3 = key.length >= 24 ? key.slice(16, 24) : k1

    const subkeys1 = generateSubkeys(k1)
    const subkeys2 = generateSubkeys(k2)
    const subkeys3 = generateSubkeys(k3)

    const ciphertext = new Uint8Array(padded.length)
    let prevBlock = iv

    for (let i = 0; i < padded.length; i += blockSize) {
        const block = padded.slice(i, i + blockSize)
        const xored = xor(bytesToBits(block), bytesToBits(prevBlock))
        const xoredBytes = bitsToBytes(xored)

        // Encrypt-Decrypt-Encrypt
        let encrypted = desEncryptBlock(xoredBytes, subkeys1)
        encrypted = desDecryptBlock(encrypted, subkeys2)
        encrypted = desEncryptBlock(encrypted, subkeys3)

        ciphertext.set(encrypted, i)
        prevBlock = encrypted
    }

    const buffer = new ArrayBuffer(ciphertext.length)
    const result = new Uint8Array(buffer)
    result.set(ciphertext)
    return result
}

/**
 * 3DES-CBC decryption (2-key or 3-key)
 */
export function tripleDesDecrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
): Uint8Array<ArrayBuffer> {
    const blockSize = 8

    // Split key into K1, K2, K3
    const k1 = key.slice(0, 8)
    const k2 = key.slice(8, 16)
    const k3 = key.length >= 24 ? key.slice(16, 24) : k1

    const subkeys1 = generateSubkeys(k1)
    const subkeys2 = generateSubkeys(k2)
    const subkeys3 = generateSubkeys(k3)

    const plaintext = new Uint8Array(ciphertext.length)
    let prevBlock = iv

    for (let i = 0; i < ciphertext.length; i += blockSize) {
        const block = ciphertext.slice(i, i + blockSize)

        // Decrypt-Encrypt-Decrypt
        let decrypted = desDecryptBlock(block, subkeys3)
        decrypted = desEncryptBlock(decrypted, subkeys2)
        decrypted = desDecryptBlock(decrypted, subkeys1)

        const xored = xor(bytesToBits(decrypted), bytesToBits(prevBlock))
        plaintext.set(bitsToBytes(xored), i)
        prevBlock = block
    }

    // Remove PKCS7 padding with validation
    const paddingLength = plaintext[plaintext.length - 1]

    // Validate padding
    if (paddingLength < 1 || paddingLength > 8) {
        throw new Error('Invalid padding: padding length out of range')
    }

    // Verify all padding bytes are correct
    for (let i = plaintext.length - paddingLength; i < plaintext.length; i++) {
        if (plaintext[i] !== paddingLength) {
            throw new Error('Invalid padding: incorrect padding bytes')
        }
    }

    const unpadded = plaintext.slice(0, plaintext.length - paddingLength)

    const buffer = new ArrayBuffer(unpadded.length)
    const result = new Uint8Array(buffer)
    result.set(unpadded)
    return result
}
