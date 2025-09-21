import forge from 'node-forge'

export type PbeAlgorithmMap = {
    SHA1_3DES_2KEY_CBC: {
        salt: Uint8Array
        iterationCount: number
    }
    SHA1_3DES_3KEY_CBC: {
        salt: Uint8Array
        iterationCount: number
    }
    SHA1_RC2_40_CBC: {
        salt: Uint8Array
        iterationCount: number
    }
    SHA1_RC2_128_CBC: {
        salt: Uint8Array
        iterationCount: number
    }
}

declare module 'pki-lite/core/crypto/index.js' {
    // Extensible interface for PBE algorithms
    export interface SymmetricEncryptionAlgorithmParamsMap
        extends PbeAlgorithmMap {}
}

type PbeAlgorithm = {
    encrypt: (
        plaintext: Uint8Array,
        password: string | Uint8Array,
        salt: Uint8Array,
        iterationCount: number,
    ) => Uint8Array
    decrypt: (
        ciphertext: Uint8Array,
        password: string | Uint8Array,
        salt: Uint8Array,
        iterationCount: number,
    ) => Uint8Array
}

const getPassword = (password: string | Uint8Array): string => {
    if (typeof password === 'string') {
        return password
    } else {
        return forge.util.binary.raw.encode(password)
    }
}

const pbeAlgorithms: { [name in keyof PbeAlgorithmMap]: PbeAlgorithm } = {
    SHA1_3DES_2KEY_CBC: {
        encrypt: (
            plaintext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const key = forge.pkcs12.generateKey(
                getPassword(password),
                forge.util.createBuffer(forge.util.binary.raw.encode(salt)),
                1,
                iterationCount,
                16, // 2-key 3DES = 16 bytes
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                forge.util.createBuffer(forge.util.binary.raw.encode(salt)),
                2,
                iterationCount,
                8, // 8-byte IV
            )

            const cipher = forge.rc2.createEncryptionCipher(key, 40)
            cipher.start(iv)
            cipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(plaintext),
                ),
            )
            cipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(cipher.output.getBytes()),
            )
        },
        decrypt: (
            ciphertext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const key = forge.pkcs12.generateKey(
                getPassword(password),
                forge.util.createBuffer(forge.util.binary.raw.encode(salt)),
                1,
                iterationCount,
                16, // 2-key 3DES = 16 bytes
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                forge.util.createBuffer(forge.util.binary.raw.encode(salt)),
                2,
                iterationCount,
                8, // 8-byte IV
            )

            const decipher = forge.rc2.createDecryptionCipher(key, 40)
            decipher.start(iv)
            decipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(ciphertext),
                ),
            )
            decipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(decipher.output.getBytes()),
            )
        },
    },
    SHA1_3DES_3KEY_CBC: {
        encrypt: (
            plaintext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const saltBuffer = forge.util.createBuffer()
            saltBuffer.putBytes(forge.util.binary.raw.encode(salt))

            const key = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                1,
                iterationCount,
                24,
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                2,
                iterationCount,
                8,
            )

            const cipher = forge.cipher.createCipher('3DES-CBC', key)
            cipher.start({
                iv,
            })
            cipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(plaintext),
                ),
            )
            cipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(cipher.output.getBytes()),
            )
        },
        decrypt: (
            ciphertext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const saltBuffer = forge.util.createBuffer()
            saltBuffer.putBytes(forge.util.binary.raw.encode(salt))

            const key = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                1,
                iterationCount,
                24,
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                2,
                iterationCount,
                8,
            )

            const decipher = forge.cipher.createDecipher('3DES-CBC', key)
            decipher.start({
                iv: iv,
            })
            decipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(ciphertext),
                ),
            )
            decipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(decipher.output.getBytes()),
            )
        },
    },
    SHA1_RC2_40_CBC: {
        encrypt: (
            plaintext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const saltBuffer = forge.util.createBuffer()
            saltBuffer.putBytes(forge.util.binary.raw.encode(salt))

            const key = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                1,
                iterationCount,
                5,
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                2,
                iterationCount,
                8,
            )

            const cipher = forge.rc2.createEncryptionCipher(key, 40)
            cipher.start(iv)
            cipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(plaintext),
                ),
            )
            cipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(cipher.output.getBytes()),
            )
        },
        decrypt: (
            ciphertext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const saltBuffer = forge.util.createBuffer()
            saltBuffer.putBytes(forge.util.binary.raw.encode(salt))
            const key = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                1,
                iterationCount,
                5,
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                2,
                iterationCount,
                8,
            )

            const decipher = forge.rc2.createDecryptionCipher(key, 40)
            decipher.start(iv)
            decipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(ciphertext),
                ),
            )
            decipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(decipher.output.getBytes()),
            )
        },
    },
    SHA1_RC2_128_CBC: {
        encrypt: (
            plaintext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const saltBuffer = forge.util.createBuffer()
            saltBuffer.putBytes(forge.util.binary.raw.encode(salt))

            const key = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                1,
                iterationCount,
                16,
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                2,
                iterationCount,
                8,
            )

            const cipher = forge.rc2.createEncryptionCipher(key, 128)
            cipher.start(iv)
            cipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(plaintext),
                ),
            )
            cipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(cipher.output.getBytes()),
            )
        },
        decrypt: (
            ciphertext: Uint8Array,
            password: string | Uint8Array,
            salt: Uint8Array,
            iterationCount: number,
        ): Uint8Array => {
            const saltBuffer = forge.util.createBuffer()
            saltBuffer.putBytes(forge.util.binary.raw.encode(salt))
            const key = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                1,
                iterationCount,
                16,
            )
            const iv = forge.pkcs12.generateKey(
                getPassword(password),
                saltBuffer,
                2,
                iterationCount,
                8,
            )

            const decipher = forge.rc2.createDecryptionCipher(key, 128)
            decipher.start(iv)
            decipher.update(
                forge.util.createBuffer(
                    forge.util.binary.raw.encode(ciphertext),
                ),
            )
            decipher.finish()
            return new Uint8Array(
                forge.util.binary.raw.decode(decipher.output.getBytes()),
            )
        },
    },
}

export function getPbeAlgorithm(name: keyof PbeAlgorithmMap): PbeAlgorithm {
    const alg = pbeAlgorithms[name]
    if (!alg) {
        throw new Error(`Unsupported PBE algorithm: ${name}`)
    }
    return alg
}
