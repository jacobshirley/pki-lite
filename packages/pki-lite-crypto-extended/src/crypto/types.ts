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

declare module 'pki-lite/core/crypto/index.js' {
    // Extensible interface for PBE algorithms
    export interface SymmetricEncryptionAlgorithmParamsMap
        extends PbeAlgorithmMap {}
}
