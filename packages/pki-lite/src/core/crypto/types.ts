import type { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import type { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import type { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import type { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'

export type NamedCurve = 'P-256' | 'P-384' | 'P-521'
export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512' | 'MD5'

// Extensible interface for asymmetric algorithms
export interface AsymmetricEncryptionAlgorithmParamsMap {
    RSA_PSS: {
        hash: HashAlgorithm
        saltLength: number
    }
    RSA_OAEP: {
        hash: HashAlgorithm
        label?: Uint8Array
        pSourceAlgorithm?: string
    }
    RSASSA_PKCS1_v1_5: {
        hash: HashAlgorithm
    }
    ECDSA: {
        hash: HashAlgorithm
        namedCurve: NamedCurve
    }
    ECDH: {
        namedCurve: NamedCurve
    }
}

// Discriminated union type
export type AsymmetricEncryptionAlgorithmParams = {
    [K in keyof AsymmetricEncryptionAlgorithmParamsMap]: {
        type: K
        params: AsymmetricEncryptionAlgorithmParamsMap[K]
    }
}[keyof AsymmetricEncryptionAlgorithmParamsMap]

export interface DerivationAlgorithmParamsMap {
    PBKDF2: {
        salt: Uint8Array
        iterationCount: number
        keyLength?: number
        hash: HashAlgorithm
    }
}

export type DerivationAlgorithmParams = {
    [K in keyof DerivationAlgorithmParamsMap]: {
        type: K
        params: DerivationAlgorithmParamsMap[K]
    }
}[keyof DerivationAlgorithmParamsMap]

export interface PbeAlgorithmParamsMap {
    PBES2: {
        derivationAlgorithm: DerivationAlgorithmParams
        encryptionAlgorithm: SymmetricEncryptionAlgorithmParams
    }
}

// Extensible interface for symmetric algorithms
export interface SymmetricEncryptionAlgorithmParamsMap
    extends PbeAlgorithmParamsMap {
    AES_128_GCM: {
        nonce: Uint8Array
        icvLen?: number
    }
    AES_192_GCM: {
        nonce: Uint8Array
        icvLen?: number
    }
    AES_256_GCM: {
        nonce: Uint8Array
        icvLen?: number
    }
    AES_128_CCM: {
        nonce: Uint8Array
        icvLen?: number
    }
    AES_192_CCM: {
        nonce: Uint8Array
        icvLen?: number
    }
    AES_256_CCM: {
        nonce: Uint8Array
        icvLen?: number
    }
    AES_128_CBC: {
        nonce: Uint8Array
        disablePadding?: boolean
    }
    AES_192_CBC: {
        nonce: Uint8Array
        disablePadding?: boolean
    }
    AES_256_CBC: {
        nonce: Uint8Array
        disablePadding?: boolean
    }
    AES_128_ECB: {
        disablePadding?: boolean
    }
    AES_192_ECB: {
        disablePadding?: boolean
    }
    AES_256_ECB: {
        disablePadding?: boolean
    }
}

export type SymmetricEncryptionAlgorithmParams = {
    [K in keyof SymmetricEncryptionAlgorithmParamsMap]: {
        type: K
        params: SymmetricEncryptionAlgorithmParamsMap[K]
    }
}[keyof SymmetricEncryptionAlgorithmParamsMap]

export type PbeAlgorithmParams = {
    [K in keyof PbeAlgorithmParamsMap]: {
        type: K
        params: PbeAlgorithmParamsMap[K]
    }
}[keyof PbeAlgorithmParamsMap]

// Extensible interface for key pair generation options
export interface KeyPairGenOptionsMap {
    RSA: {
        keySize?: number
        publicExponent?: number
        hash?: HashAlgorithm
    }
    EC: {
        namedCurve?: NamedCurve
    }
}

export type KeyPairGenOptions = {
    [K in keyof KeyPairGenOptionsMap]: {
        algorithm: K
        params?: KeyPairGenOptionsMap[K]
    }
}[keyof KeyPairGenOptionsMap]

export type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array }

export interface CryptoProvider {
    /**
     * Computes the digest of the given data using the specified hash algorithm.
     *
     * @param data The data to digest
     * @param algorithm The hash algorithm to use
     * @returns Promise resolving to the hash digest as a Uint8Array
     */
    digest(data: Uint8Array, hash: HashAlgorithm): Promise<Uint8Array>

    /**
     * Generates a random byte array of the specified length.
     *
     * @param length The length of the byte array to generate
     * @returns A Uint8Array containing random bytes
     */
    getRandomValues(length: number): Uint8Array

    /**
     * Signs the given data using the specified private key and algorithm.
     *
     * @param data The data to sign
     * @param privateKeyInfo The private key information
     * @param algorithm The signature algorithm to use
     * @returns Promise resolving to the signature as a Uint8Array
     */
    sign(
        data: Uint8Array,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array>

    /**
     * Verifies the given signature using the specified public key and algorithm.
     *
     * @param data The data that was signed
     * @param publicKeyInfo The key information
     * @param signature The signature to verify
     * @param algorithm The signature algorithm to use
     * @returns Promise resolving to a boolean indicating if the signature is valid
     */
    verify(
        data: Uint8Array,
        publicKeyInfo: SubjectPublicKeyInfo,
        signature: Uint8Array,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<boolean>

    /**
     * Encrypts the given data using the specified public key and asymmetric algorithm.
     *
     * @param data The data to encrypt
     * @param publicKeyInfo The public key information
     * @param algorithm The encryption algorithm to use
     * @returns Promise resolving to the encrypted data as a Uint8Array
     */
    encrypt(
        data: Uint8Array,
        publicKeyInfo: SubjectPublicKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array>

    /**
     * Decrypts the given data using the specified private key and asymmetric algorithm.
     *
     * @param data The data to decrypt
     * @param privateKeyInfo The private key information
     * @param algorithm The decryption algorithm to use
     * @returns Promise resolving to the decrypted data as a Uint8Array
     */
    decrypt(
        data: Uint8Array,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array>

    /**
     * Encrypts the given data using the specified symmetric key and algorithm.
     *
     * @param data The data to encrypt
     * @param key The symmetric key to use for encryption
     * @param algorithm The encryption algorithm to use
     * @returns Promise resolving to the encrypted data as a Uint8Array
     */
    encryptSymmetric(
        data: Uint8Array,
        key: Uint8Array,
        algorithm: SymmetricEncryptionAlgorithmParams | PbeAlgorithmParams,
    ): Promise<Uint8Array>

    /**
     * Decrypts the given data using the specified symmetric key and algorithm.
     *
     * @param data The data to decrypt
     * @param key The symmetric key to use for decryption
     * @param algorithm The decryption algorithm to use
     * @returns Promise resolving to the decrypted data as a Uint8Array
     */
    decryptSymmetric(
        data: Uint8Array,
        key: Uint8Array,
        algorithm: SymmetricEncryptionAlgorithmParams | PbeAlgorithmParams,
    ): Promise<Uint8Array>

    /**
     * Generates a symmetric key for the specified encryption algorithm.
     *
     * @param algorithm The encryption algorithm to use
     * @returns The generated symmetric key as a Uint8Array
     */
    generateSymmetricKey(
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Uint8Array

    /**
     * Generates an asymmetric key pair for the specified algorithm and options.
     *
     * @param options Configuration options including algorithm, key size, and other parameters
     * @returns A Promise that resolves to an object containing the public and private keys
     */
    generateKeyPair(options: KeyPairGenOptions): Promise<KeyPair>

    /**
     * Derives a cryptographic key from a password using the specified algorithm.
     *
     * @param password The password or key material to derive from
     * @param algorithm The key derivation algorithm parameters
     * @returns Promise resolving to the derived key as a Uint8Array
     */
    deriveKey(
        password: string | Uint8Array,
        algorithm: PbeAlgorithmParams,
    ): Promise<Uint8Array>

    /**
     * Gets the EC curve parameters for a given asymmetric encryption algorithm.
     *
     * @param algorithm The asymmetric encryption algorithm parameters
     * @returns EC curve parameters as a Uint8Array or ObjectIdentifier
     */
    getEcCurveParameters(
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Uint8Array | ObjectIdentifier

    /**
     * Converts asymmetric encryption algorithm parameters to a signature algorithm identifier.
     *
     * @param algorithm The asymmetric encryption algorithm parameters
     * @returns Signature algorithm as a Uint8Array or AlgorithmIdentifier
     */
    signatureAlgorithm(
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Uint8Array | AlgorithmIdentifier

    /**
     * Converts a hash algorithm to a digest algorithm identifier.
     *
     * @param algorithm The hash algorithm
     * @returns Digest algorithm as a Uint8Array or AlgorithmIdentifier
     */
    digestAlgorithm(algorithm: HashAlgorithm): Uint8Array | AlgorithmIdentifier

    /**
     * Converts asymmetric encryption algorithm parameters to a key encryption algorithm identifier.
     *
     * @param encryptionParams The asymmetric encryption algorithm parameters
     * @returns Key encryption algorithm as an AlgorithmIdentifier
     */
    keyEncryptionAlgorithm(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): AlgorithmIdentifier

    /**
     * Converts symmetric encryption algorithm parameters to a content encryption algorithm identifier.
     *
     * @param encryptionParams The symmetric encryption algorithm parameters
     * @returns Content encryption algorithm as an AlgorithmIdentifier
     */
    contentEncryptionAlgorithm(
        encryptionParams: SymmetricEncryptionAlgorithmParams,
    ): AlgorithmIdentifier

    /**
     * Converts an ASN.1 algorithm identifier to symmetric encryption algorithm parameters.
     *
     * @param algorithm The ASN.1 algorithm identifier
     * @returns Symmetric encryption algorithm parameters
     */
    toSymmetricEncryptionAlgorithmParams(
        algorithm: AlgorithmIdentifier,
    ): SymmetricEncryptionAlgorithmParams

    /**
     * Converts an ASN.1 algorithm identifier to asymmetric encryption algorithm parameters.
     *
     * @param algorithm The ASN.1 algorithm identifier
     * @param publicKeyInfo Optional public key information for context
     * @returns Asymmetric encryption algorithm parameters
     */
    toAsymmetricEncryptionAlgorithmParams(
        algorithm: AlgorithmIdentifier,
        publicKeyInfo?: SubjectPublicKeyInfo,
    ): AsymmetricEncryptionAlgorithmParams

    /**
     * Extracts the EC named curve from an algorithm identifier or public key.
     *
     * @param algorithm The ASN.1 algorithm identifier
     * @param publicKeyInfo Optional public key information to extract curve from
     * @returns The EC named curve identifier
     */
    getEcNamedCurve(
        algorithm: AlgorithmIdentifier,
        publicKeyInfo?: SubjectPublicKeyInfo,
    ): NamedCurve

    /**
     * Converts an ASN.1 algorithm identifier to a hash algorithm.
     *
     * @param algorithm The ASN.1 algorithm identifier
     * @returns The hash algorithm
     */
    toHashAlgorithm(algorithm: AlgorithmIdentifier): HashAlgorithm
}
