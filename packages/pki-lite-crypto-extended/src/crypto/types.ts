/**
 * Parameters for supported PBE algorithms
 */
export type PbeAlgorithmMap = {
    SHA1_3DES_2KEY_CBC: {
        salt: Uint8Array<ArrayBuffer>
        iterationCount: number
    }
    SHA1_3DES_3KEY_CBC: {
        salt: Uint8Array<ArrayBuffer>
        iterationCount: number
    }
    SHA1_RC2_40_CBC: {
        salt: Uint8Array<ArrayBuffer>
        iterationCount: number
    }
    SHA1_RC2_128_CBC: {
        salt: Uint8Array<ArrayBuffer>
        iterationCount: number
    }
}

/**
 * Parameters for the other legacy ciphers this package adds
 */
export type LegacyCipherMap = {
    /** Triple DES (EDE, three keys) in CBC mode: des-ede3-cbc, 1.2.840.113549.3.7 */
    DES_EDE3_CBC: {
        nonce: Uint8Array<ArrayBuffer>
    }
}

declare module 'pki-lite/core/crypto/index.js' {
    // Extensible interface for PBE algorithms and legacy ciphers
    export interface SymmetricEncryptionAlgorithmParamsMap
        extends PbeAlgorithmMap,
            LegacyCipherMap {}
}
