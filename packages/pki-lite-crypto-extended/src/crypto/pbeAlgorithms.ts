import { WebCryptoProvider } from 'pki-lite/core/crypto/index.js'
import { PbeAlgorithmMap } from './types.js'
import { tripleDesEncrypt, tripleDesDecrypt } from './des.js'
import { rc2Encrypt, rc2Decrypt } from './rc2.js'

type PbeAlgorithm = {
    encrypt: (
        plaintext: Uint8Array<ArrayBuffer>,
        password: string | Uint8Array<ArrayBuffer>,
        salt: Uint8Array<ArrayBuffer>,
        iterationCount: number,
    ) => Promise<Uint8Array<ArrayBuffer>>
    decrypt: (
        ciphertext: Uint8Array<ArrayBuffer>,
        password: string | Uint8Array<ArrayBuffer>,
        salt: Uint8Array<ArrayBuffer>,
        iterationCount: number,
    ) => Promise<Uint8Array<ArrayBuffer>>
}

const provider = new WebCryptoProvider()

const pbeAlgorithms: { [name in keyof PbeAlgorithmMap]: PbeAlgorithm } = {
    SHA1_3DES_2KEY_CBC: {
        encrypt: async (
            plaintext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (16 bytes for 2-key 3DES)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                16,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return tripleDesEncrypt(plaintext, key, iv)
        },
        decrypt: async (
            ciphertext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (16 bytes for 2-key 3DES)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                16,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return tripleDesDecrypt(ciphertext, key, iv)
        },
    },
    SHA1_3DES_3KEY_CBC: {
        encrypt: async (
            plaintext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (24 bytes for 3-key 3DES)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                24,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return tripleDesEncrypt(plaintext, key, iv)
        },
        decrypt: async (
            ciphertext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (24 bytes for 3-key 3DES)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                24,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return tripleDesDecrypt(ciphertext, key, iv)
        },
    },
    SHA1_RC2_40_CBC: {
        encrypt: async (
            plaintext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (5 bytes for 40-bit RC2)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                5,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return rc2Encrypt(plaintext, key, iv, 40)
        },
        decrypt: async (
            ciphertext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (5 bytes for 40-bit RC2)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                5,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return rc2Decrypt(ciphertext, key, iv, 40)
        },
    },
    SHA1_RC2_128_CBC: {
        encrypt: async (
            plaintext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (16 bytes for 128-bit RC2)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                16,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return rc2Encrypt(plaintext, key, iv, 128)
        },
        decrypt: async (
            ciphertext: Uint8Array<ArrayBuffer>,
            password: string | Uint8Array<ArrayBuffer>,
            salt: Uint8Array<ArrayBuffer>,
            iterationCount: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            // Derive key (16 bytes for 128-bit RC2)
            const key = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                16,
                'encryption',
                'SHA-1',
            )

            // Derive IV (8 bytes)
            const iv = await provider.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                8,
                'iv',
                'SHA-1',
            )

            return rc2Decrypt(ciphertext, key, iv, 128)
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
