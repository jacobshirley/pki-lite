/**
 * Custom MD5 implementation
 * Based on RFC 1321: The MD5 Message-Digest Algorithm
 *
 * WARNING: MD5 is cryptographically broken and should not be used for security purposes.
 * This implementation is provided only for compatibility with legacy systems.
 */

// MD5 constants - sine-based values
const K = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
])

// Shift amounts for each round
const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5,
    9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
    16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10,
    15, 21,
]

/**
 * Left rotate a 32-bit integer
 */
function rotateLeft(x: number, n: number): number {
    return (x << n) | (x >>> (32 - n))
}

/**
 * MD5 auxiliary functions
 */
function F(x: number, y: number, z: number): number {
    return (x & y) | (~x & z)
}

function G(x: number, y: number, z: number): number {
    return (x & z) | (y & ~z)
}

function H(x: number, y: number, z: number): number {
    return x ^ y ^ z
}

function I(x: number, y: number, z: number): number {
    return y ^ (x | ~z)
}

/**
 * Pad the message according to MD5 specification
 */
function padMessage(message: Uint8Array): Uint8Array {
    const msgLen = message.length
    const bitLen = msgLen * 8

    // Calculate padding length (message + 1 bit + zeros + 64-bit length)
    // Must be congruent to 448 mod 512 (56 mod 64 bytes)
    const padLen = (56 - ((msgLen + 1) % 64) + 64) % 64
    const totalLen = msgLen + 1 + padLen + 8

    const padded = new Uint8Array(totalLen)

    // Copy original message
    padded.set(message, 0)

    // Append 0x80 (bit '1' followed by zeros)
    padded[msgLen] = 0x80

    // Append original message length in bits as 64-bit little-endian
    const view = new DataView(padded.buffer)
    view.setUint32(totalLen - 8, bitLen, true) // Low 32 bits
    view.setUint32(totalLen - 4, Math.floor(bitLen / 0x100000000), true) // High 32 bits

    return padded
}

/**
 * Process a single 512-bit (64-byte) block
 */
function processBlock(block: Uint8Array, state: Uint32Array): void {
    // Break block into sixteen 32-bit little-endian words
    const M = new Uint32Array(16)
    const view = new DataView(block.buffer, block.byteOffset, 64)
    for (let i = 0; i < 16; i++) {
        M[i] = view.getUint32(i * 4, true)
    }

    // Initialize working variables
    let A = state[0]
    let B = state[1]
    let C = state[2]
    let D = state[3]

    // Main loop - 64 operations in 4 rounds
    for (let i = 0; i < 64; i++) {
        let f: number
        let g: number

        if (i < 16) {
            f = F(B, C, D)
            g = i
        } else if (i < 32) {
            f = G(B, C, D)
            g = (5 * i + 1) % 16
        } else if (i < 48) {
            f = H(B, C, D)
            g = (3 * i + 5) % 16
        } else {
            f = I(B, C, D)
            g = (7 * i) % 16
        }

        const temp = D
        D = C
        C = B
        B = (B + rotateLeft((A + f + K[i] + M[g]) >>> 0, S[i])) >>> 0
        A = temp
    }

    // Add this block's hash to result so far
    state[0] = (state[0] + A) >>> 0
    state[1] = (state[1] + B) >>> 0
    state[2] = (state[2] + C) >>> 0
    state[3] = (state[3] + D) >>> 0
}

/**
 * Compute MD5 hash of input data
 * @param data The input data to hash
 * @returns The 16-byte MD5 hash
 */
export function md5(data: Uint8Array): Uint8Array<ArrayBuffer> {
    // Initialize MD5 state (little-endian)
    const state = new Uint32Array([
        0x67452301, // A
        0xefcdab89, // B
        0x98badcfe, // C
        0x10325476, // D
    ])

    // Pad the message
    const padded = padMessage(data)

    // Process each 512-bit (64-byte) block
    for (let offset = 0; offset < padded.length; offset += 64) {
        const block = padded.subarray(offset, offset + 64)
        processBlock(block, state)
    }

    // Convert state to byte array (little-endian)
    const buffer = new ArrayBuffer(16)
    const result = new Uint8Array(buffer)
    const view = new DataView(buffer)

    for (let i = 0; i < 4; i++) {
        view.setUint32(i * 4, state[i], true)
    }

    return result
}
