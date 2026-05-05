import { RSAPublicKey } from 'pki-lite/keys/RSAPublicKey.js'
import { RSAPrivateKey } from 'pki-lite/keys/RSAPrivateKey.js'

/**
 * Convert a Uint8Array to a bigint (big-endian)
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i])
    }
    return result
}

/**
 * Convert a bigint to a Uint8Array with a specific length (big-endian)
 * Pads with leading zeros if necessary
 */
export function bigIntToBytes(
    value: bigint,
    length: number,
): Uint8Array<ArrayBuffer> {
    const buffer = new ArrayBuffer(length)
    const result = new Uint8Array(buffer)
    let v = value
    for (let i = length - 1; i >= 0; i--) {
        result[i] = Number(v & 0xffn)
        v = v >> 8n
    }
    return result
}

/**
 * Modular exponentiation: base^exponent mod modulus
 * Uses the built-in bigint support in JavaScript
 */
export function modPow(
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint {
    if (modulus === 1n) return 0n
    let result = 1n
    base = base % modulus
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus
        }
        exponent = exponent >> 1n
        base = (base * base) % modulus
    }
    return result
}

/**
 * Generate random non-zero bytes for PKCS#1 v1.5 padding
 */
export function generateRandomNonZeroBytes(
    length: number,
): Uint8Array<ArrayBuffer> {
    const buffer = new ArrayBuffer(length)
    const bytes = new Uint8Array(buffer)
    const random = crypto.getRandomValues(new Uint8Array(length))
    for (let i = 0; i < length; i++) {
        // Ensure non-zero bytes by mapping 0 to a random value between 1-255
        bytes[i] = random[i] === 0 ? (random[i] + 1) % 256 || 1 : random[i]
    }
    return bytes
}

/**
 * Apply RSASSA-PKCS1-v1_5 encryption padding (block type 0x02)
 * Format: 0x00 || 0x02 || PS || 0x00 || M
 * where PS is at least 8 random non-zero bytes
 */
export function rsaesPkcs1v15Pad(
    message: Uint8Array,
    modulusLength: number,
): Uint8Array<ArrayBuffer> {
    // k is the length of the modulus in bytes
    const k = modulusLength
    const mLen = message.length

    // Check if message is too long
    if (mLen > k - 11) {
        throw new Error(
            `Message too long for RSA key size. Maximum message length is ${k - 11} bytes`,
        )
    }

    // Calculate padding string length (at least 8 bytes)
    const psLen = k - mLen - 3

    // Build the padded message: 0x00 || 0x02 || PS || 0x00 || M
    const buffer = new ArrayBuffer(k)
    const padded = new Uint8Array(buffer)
    padded[0] = 0x00
    padded[1] = 0x02

    // Generate random non-zero padding
    const ps = generateRandomNonZeroBytes(psLen)
    padded.set(ps, 2)

    // Separator
    padded[2 + psLen] = 0x00

    // Message
    padded.set(message, 2 + psLen + 1)

    return padded
}

/**
 * Remove RSASSA-PKCS1-v1_5 decryption padding (block type 0x02)
 * Expects format: 0x00 || 0x02 || PS || 0x00 || M
 */
export function rsaesPkcs1v15Unpad(
    padded: Uint8Array,
): Uint8Array<ArrayBuffer> {
    // Check minimum length
    if (padded.length < 11) {
        throw new Error('Decryption error: invalid padding length')
    }

    // Check first byte is 0x00
    if (padded[0] !== 0x00) {
        throw new Error('Decryption error: invalid padding format (byte 0)')
    }

    // Check second byte is 0x02 (encryption block type)
    if (padded[1] !== 0x02) {
        throw new Error('Decryption error: invalid padding format (byte 1)')
    }

    // Find the 0x00 separator after the padding string
    let separatorIndex = -1
    for (let i = 2; i < padded.length; i++) {
        if (padded[i] === 0x00) {
            separatorIndex = i
            break
        }
    }

    // Check separator was found and padding is at least 8 bytes
    if (separatorIndex === -1 || separatorIndex < 10) {
        throw new Error('Decryption error: invalid padding format (separator)')
    }

    // Extract the message
    const message = padded.slice(separatorIndex + 1)
    // Ensure proper ArrayBuffer type
    const buffer = new ArrayBuffer(message.length)
    const result = new Uint8Array(buffer)
    result.set(message)
    return result
}

/**
 * Perform RSA encryption with PKCS#1 v1.5 padding
 * @param data - The plaintext data to encrypt
 * @param publicKey - The RSA public key
 * @returns The encrypted ciphertext
 */
export function rsaEncrypt(
    data: Uint8Array<ArrayBuffer>,
    publicKey: RSAPublicKey,
): Uint8Array<ArrayBuffer> {
    const modulus = bytesToBigInt(publicKey.modulus)
    const exponent = bytesToBigInt(publicKey.publicExponent)
    const modulusLength = publicKey.modulus.length

    // Apply PKCS#1 v1.5 padding (block type 0x02)
    const padded = rsaesPkcs1v15Pad(data, modulusLength)

    // Convert padded message to bigint
    const m = bytesToBigInt(padded)

    // Perform RSA encryption: c = m^e mod n
    const c = modPow(m, exponent, modulus)

    // Convert to bytes with proper length
    return bigIntToBytes(c, modulusLength)
}

/**
 * Perform RSA decryption with PKCS#1 v1.5 padding
 * @param data - The ciphertext data to decrypt
 * @param privateKey - The RSA private key
 * @returns The decrypted plaintext
 */
export function rsaDecrypt(
    data: Uint8Array<ArrayBuffer>,
    privateKey: RSAPrivateKey,
): Uint8Array<ArrayBuffer> {
    const modulus = bytesToBigInt(privateKey.modulus)
    const exponent = bytesToBigInt(privateKey.privateExponent)
    const modulusLength = privateKey.modulus.length

    // Convert ciphertext to bigint
    const c = bytesToBigInt(data)

    // Perform RSA decryption: m = c^d mod n
    const m = modPow(c, exponent, modulus)

    // Convert to bytes with proper length
    const padded = bigIntToBytes(m, modulusLength)

    // Remove PKCS#1 v1.5 padding
    return rsaesPkcs1v15Unpad(padded)
}
