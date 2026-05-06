/**
 * RC2 implementation for legacy PKCS#12 support
 * Implements RC2 block cipher with variable key length
 */

const PITABLE = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79,
    0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
    0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5,
    0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22,
    0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
    0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f,
    0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b,
    0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
    0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde,
    0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e,
    0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
    0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85,
    0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10,
    0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
    0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b,
    0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68,
    0xfe, 0x7f, 0xc1, 0xad,
]

function rotl16(value: number, shift: number): number {
    return ((value << shift) | (value >>> (16 - shift))) & 0xffff
}

function rotr16(value: number, shift: number): number {
    return ((value >>> shift) | (value << (16 - shift))) & 0xffff
}

/**
 * Expand key using RC2's key schedule
 */
function expandKey(key: Uint8Array, effectiveBits: number): Uint16Array {
    const L = new Uint8Array(128)
    L.set(key)

    // Phase 1: Expand key to 128 bytes
    for (let i = key.length; i < 128; i++) {
        L[i] = PITABLE[(L[i - 1] + L[i - key.length]) & 0xff]
    }

    // Phase 2: Apply effective key bits
    const T8 = (effectiveBits + 7) >> 3
    const TM = 255 % (1 << (8 + effectiveBits - 8 * T8))
    L[128 - T8] = PITABLE[L[128 - T8] & TM]

    for (let i = 127 - T8; i >= 0; i--) {
        L[i] = PITABLE[L[i + 1] ^ L[i + T8]]
    }

    // Convert to 16-bit words
    const K = new Uint16Array(64)
    for (let i = 0; i < 64; i++) {
        K[i] = L[2 * i] + (L[2 * i + 1] << 8)
    }

    return K
}

/**
 * RC2 encryption of a single 8-byte block
 */
function rc2EncryptBlock(
    block: Uint8Array,
    expandedKey: Uint16Array,
): Uint8Array<ArrayBuffer> {
    let R0 = block[0] + (block[1] << 8)
    let R1 = block[2] + (block[3] << 8)
    let R2 = block[4] + (block[5] << 8)
    let R3 = block[6] + (block[7] << 8)

    let j = 0

    // 16 rounds
    for (let i = 0; i < 16; i++) {
        // Mixing round
        R0 = (R0 + expandedKey[j++] + (R3 & R2) + (~R3 & R1)) & 0xffff
        R0 = rotl16(R0, 1)

        R1 = (R1 + expandedKey[j++] + (R0 & R3) + (~R0 & R2)) & 0xffff
        R1 = rotl16(R1, 2)

        R2 = (R2 + expandedKey[j++] + (R1 & R0) + (~R1 & R3)) & 0xffff
        R2 = rotl16(R2, 3)

        R3 = (R3 + expandedKey[j++] + (R2 & R1) + (~R2 & R0)) & 0xffff
        R3 = rotl16(R3, 5)

        // Mashing round (after rounds 5 and 11)
        if (i === 4 || i === 10) {
            R0 = (R0 + expandedKey[R3 & 63]) & 0xffff
            R1 = (R1 + expandedKey[R0 & 63]) & 0xffff
            R2 = (R2 + expandedKey[R1 & 63]) & 0xffff
            R3 = (R3 + expandedKey[R2 & 63]) & 0xffff
        }
    }

    const result = new Uint8Array(8)
    result[0] = R0 & 0xff
    result[1] = (R0 >> 8) & 0xff
    result[2] = R1 & 0xff
    result[3] = (R1 >> 8) & 0xff
    result[4] = R2 & 0xff
    result[5] = (R2 >> 8) & 0xff
    result[6] = R3 & 0xff
    result[7] = (R3 >> 8) & 0xff

    return result
}

/**
 * RC2 decryption of a single 8-byte block
 */
function rc2DecryptBlock(
    block: Uint8Array,
    expandedKey: Uint16Array,
): Uint8Array {
    let R0 = block[0] + (block[1] << 8)
    let R1 = block[2] + (block[3] << 8)
    let R2 = block[4] + (block[5] << 8)
    let R3 = block[6] + (block[7] << 8)

    let j = 63

    // 16 rounds in reverse
    for (let i = 15; i >= 0; i--) {
        // Mashing round (before rounds 11 and 5 in reverse)
        if (i === 10 || i === 4) {
            R3 = (R3 - expandedKey[R2 & 63]) & 0xffff
            R2 = (R2 - expandedKey[R1 & 63]) & 0xffff
            R1 = (R1 - expandedKey[R0 & 63]) & 0xffff
            R0 = (R0 - expandedKey[R3 & 63]) & 0xffff
        }

        // Mixing round in reverse
        R3 = rotr16(R3, 5)
        R3 = (R3 - expandedKey[j--] - (R2 & R1) - (~R2 & R0)) & 0xffff

        R2 = rotr16(R2, 3)
        R2 = (R2 - expandedKey[j--] - (R1 & R0) - (~R1 & R3)) & 0xffff

        R1 = rotr16(R1, 2)
        R1 = (R1 - expandedKey[j--] - (R0 & R3) - (~R0 & R2)) & 0xffff

        R0 = rotr16(R0, 1)
        R0 = (R0 - expandedKey[j--] - (R3 & R2) - (~R3 & R1)) & 0xffff
    }

    const result = new Uint8Array(8)
    result[0] = R0 & 0xff
    result[1] = (R0 >> 8) & 0xff
    result[2] = R1 & 0xff
    result[3] = (R1 >> 8) & 0xff
    result[4] = R2 & 0xff
    result[5] = (R2 >> 8) & 0xff
    result[6] = R3 & 0xff
    result[7] = (R3 >> 8) & 0xff

    return result
}

/**
 * RC2-CBC encryption
 */
export function rc2Encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    effectiveBits: number,
): Uint8Array<ArrayBuffer> {
    const blockSize = 8

    // Pad to 8-byte blocks
    const paddingLength =
        blockSize - (plaintext.length % blockSize) || blockSize
    const padded = new Uint8Array(plaintext.length + paddingLength)
    padded.set(plaintext)
    for (let i = plaintext.length; i < padded.length; i++) {
        padded[i] = paddingLength
    }

    const expandedKey = expandKey(key, effectiveBits)
    const ciphertext = new Uint8Array(padded.length)
    let prevBlock: Uint8Array<ArrayBuffer> = iv.slice(0, blockSize)

    for (let i = 0; i < padded.length; i += blockSize) {
        const block = padded.slice(i, i + blockSize)
        // XOR with previous ciphertext block (CBC mode)
        for (let j = 0; j < blockSize; j++) {
            block[j] ^= prevBlock[j]
        }

        const encrypted = rc2EncryptBlock(block, expandedKey)
        ciphertext.set(encrypted, i)
        prevBlock = encrypted
    }

    const buffer = new ArrayBuffer(ciphertext.length)
    const result = new Uint8Array(buffer)
    result.set(ciphertext)
    return result
}

/**
 * RC2-CBC decryption
 */
export function rc2Decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    effectiveBits: number,
): Uint8Array<ArrayBuffer> {
    const blockSize = 8
    const expandedKey = expandKey(key, effectiveBits)
    const plaintext = new Uint8Array(ciphertext.length)
    let prevBlock = iv.slice(0, blockSize)

    for (let i = 0; i < ciphertext.length; i += blockSize) {
        const block = ciphertext.slice(i, i + blockSize)
        const decrypted = rc2DecryptBlock(block, expandedKey)

        // XOR with previous ciphertext block (CBC mode)
        for (let j = 0; j < blockSize; j++) {
            decrypted[j] ^= prevBlock[j]
        }

        plaintext.set(decrypted, i)
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
