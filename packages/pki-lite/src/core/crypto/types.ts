import type { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import type { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import type { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import type { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'

/**
 * Supported named elliptic curves for ECDSA and ECDH operations.
 * These correspond to NIST P-curves supported by Web Crypto API.
 */
export type NamedCurve = 'P-256' | 'P-384' | 'P-521'

/**
 * Supported cryptographic hash algorithms.
 * Note: MD5 is only available with extended crypto providers.
 */
export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512' | 'MD5'

/**
 * Parameter mapping for asymmetric encryption and signature algorithms.
 * Each algorithm type has its own specific parameter requirements.
 */
export interface AsymmetricEncryptionAlgorithmParamsMap {
    /**
     * RSA Probabilistic Signature Scheme (PSS) parameters.
     */
    RSA_PSS: {
        /** Hash algorithm for signature generation */
        hash: HashAlgorithm
        /** Salt length in bytes */
        saltLength: number
    }
    /**
     * RSA Optimal Asymmetric Encryption Padding (OAEP) parameters.
     */
    RSA_OAEP: {
        /** Hash algorithm for mask generation */
        hash: HashAlgorithm
        /** Optional label for encryption */
        label?: Uint8Array<ArrayBuffer>
        /** Mask generation function algorithm */
        pSourceAlgorithm?: string
    }
    /**
     * RSA PKCS#1 v1.5 signature parameters.
     */
    RSASSA_PKCS1_v1_5: {
        /** Hash algorithm for signature */
        hash: HashAlgorithm
    }
    /**
     * Elliptic Curve Digital Signature Algorithm parameters.
     */
    ECDSA: {
        /** Hash algorithm for signature */
        hash: HashAlgorithm
        /** Named curve identifier */
        namedCurve: NamedCurve
    }
    /**
     * Elliptic Curve Diffie-Hellman parameters.
     */
    ECDH: {
        /** Named curve identifier */
        namedCurve: NamedCurve
    }
}

/**
 * Discriminated union type for asymmetric algorithm parameters.
 * Each algorithm type includes its specific parameter set.
 */
export type AsymmetricEncryptionAlgorithmParams = {
    [K in keyof AsymmetricEncryptionAlgorithmParamsMap]: {
        type: K
        params: AsymmetricEncryptionAlgorithmParamsMap[K]
    }
}[keyof AsymmetricEncryptionAlgorithmParamsMap]

/**
 * Parameter mapping for key derivation algorithms.
 */
export interface DerivationAlgorithmParamsMap {
    /**
     * Password-Based Key Derivation Function 2 parameters.
     */
    PBKDF2: {
        /** Salt value for key derivation */
        salt: Uint8Array<ArrayBuffer>
        /** Number of iterations */
        iterationCount: number
        /** Desired key length in bytes (optional) */
        keyLength?: number
        /** Hash algorithm for HMAC */
        hash: HashAlgorithm
    }
}

/**
 * Discriminated union type for key derivation algorithm parameters.
 */
export type DerivationAlgorithmParams = {
    [K in keyof DerivationAlgorithmParamsMap]: {
        type: K
        params: DerivationAlgorithmParamsMap[K]
    }
}[keyof DerivationAlgorithmParamsMap]

/**
 * Parameter mapping for password-based encryption algorithms.
 */
export interface PbeAlgorithmParamsMap {
    /**
     * Password-Based Encryption Scheme 2 parameters.
     */
    PBES2: {
        /** Key derivation algorithm and parameters */
        derivationAlgorithm: DerivationAlgorithmParams
        /** Symmetric encryption algorithm and parameters */
        encryptionAlgorithm: SymmetricEncryptionAlgorithmParams
    }
}

/**
 * Parameter mapping for symmetric encryption algorithms.
 * Includes both standalone symmetric algorithms and password-based encryption.
 */
export interface SymmetricEncryptionAlgorithmParamsMap
    extends PbeAlgorithmParamsMap {
    /**
     * AES-128 in Galois/Counter Mode parameters.
     */
    AES_128_GCM: {
        /** Initialization vector/nonce */
        nonce: Uint8Array<ArrayBuffer>
        /** Authentication tag length in bytes */
        icvLen?: number
    }
    /**
     * AES-192 in Galois/Counter Mode parameters.
     */
    AES_192_GCM: {
        /** Initialization vector/nonce */
        nonce: Uint8Array<ArrayBuffer>
        /** Authentication tag length in bytes */
        icvLen?: number
    }
    /**
     * AES-256 in Galois/Counter Mode parameters.
     */
    AES_256_GCM: {
        /** Initialization vector/nonce */
        nonce: Uint8Array<ArrayBuffer>
        /** Authentication tag length in bytes */
        icvLen?: number
    }
    /**
     * AES-128 in Counter with CBC-MAC Mode parameters.
     */
    AES_128_CCM: {
        /** Initialization vector/nonce */
        nonce: Uint8Array<ArrayBuffer>
        /** Authentication tag length in bytes */
        icvLen?: number
    }
    AES_192_CCM: {
        nonce: Uint8Array<ArrayBuffer>
        icvLen?: number
    }
    AES_256_CCM: {
        nonce: Uint8Array<ArrayBuffer>
        icvLen?: number
    }
    AES_128_CBC: {
        nonce: Uint8Array<ArrayBuffer>
        disablePadding?: boolean
    }
    AES_192_CBC: {
        nonce: Uint8Array<ArrayBuffer>
        disablePadding?: boolean
    }
    AES_256_CBC: {
        nonce: Uint8Array<ArrayBuffer>
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

export type KeyPair = {
    publicKey: Uint8Array<ArrayBuffer>
    privateKey: Uint8Array<ArrayBuffer>
}

/**
 * Interface defining the cryptographic operations required by the PKI library.
 *
 * This interface abstracts cryptographic operations to allow different implementations
 * based on available platforms and algorithm requirements. The default WebCryptoProvider
 * uses the Web Crypto API, while extended providers can support additional algorithms
 * and legacy cryptographic functions.
 *
 * Implementations must provide:
 * - Hashing operations for message digests
 * - Digital signature creation and verification
 * - Asymmetric encryption and decryption
 * - Symmetric encryption and decryption
 * - Key derivation functions
 * - Random number generation
 *
 * @example
 * ```typescript
 * class CustomCryptoProvider implements CryptoProvider {
 *     async digest(data: Uint8Array<ArrayBuffer>, algorithm: HashAlgorithm): Promise<Uint8Array<ArrayBuffer>> {
 *         // Custom hash implementation
 *         return customHash(data, algorithm)
 *     }
 *
 *     // Implement other required methods...
 * }
 *
 * // Use custom provider
 * setCryptoProvider(new CustomCryptoProvider())
 * ```
 */
export interface CryptoProvider {
    /**
     * Computes the cryptographic hash digest of the given data.
     *
     * @param data The data to hash
     * @param algorithm The hash algorithm to use (SHA-1, SHA-256, etc.)
     * @returns Promise resolving to the hash digest bytes
     */
    digest(
        data: Uint8Array<ArrayBuffer>,
        hash: HashAlgorithm,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Generates cryptographically secure random bytes.
     *
     * @param length The number of random bytes to generate
     * @returns Array containing the random bytes
     */
    getRandomValues(length: number): Uint8Array<ArrayBuffer>

    /**
     * Creates a digital signature for the given data.
     *
     * @param data The data to sign
     * @param privateKeyInfo The signer's private key
     * @param algorithm The signature algorithm and parameters
     * @returns Promise resolving to the signature bytes
     */
    sign(
        data: Uint8Array<ArrayBuffer>,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Verifies a digital signature against the original data.
     *
     * @param data The original data that was signed
     * @param publicKeyInfo The signer's public key
     * @param signature The signature to verify
     * @param algorithm The signature algorithm and parameters
     * @returns Promise resolving to true if signature is valid
     */
    verify(
        data: Uint8Array<ArrayBuffer>,
        publicKeyInfo: SubjectPublicKeyInfo,
        signature: Uint8Array<ArrayBuffer>,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<boolean>

    /**
     * Encrypts data using asymmetric (public key) cryptography.
     *
     * @param data The data to encrypt
     * @param publicKeyInfo The public key information
     * @param algorithm The encryption algorithm to use
     * @returns Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>
     */
    encrypt(
        data: Uint8Array<ArrayBuffer>,
        publicKeyInfo: SubjectPublicKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Decrypts the given data using the specified private key and asymmetric algorithm.
     *
     * @param data The data to decrypt
     * @param privateKeyInfo The private key information
     * @param algorithm The decryption algorithm to use
     * @returns Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>
     */
    decrypt(
        data: Uint8Array<ArrayBuffer>,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Encrypts the given data using the specified symmetric key and algorithm.
     *
     * @param data The data to encrypt
     * @param key The symmetric key to use for encryption
     * @param algorithm The encryption algorithm to use
     * @returns Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>
     */
    encryptSymmetric(
        data: Uint8Array<ArrayBuffer>,
        key: Uint8Array<ArrayBuffer>,
        algorithm: SymmetricEncryptionAlgorithmParams | PbeAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Decrypts the given data using the specified symmetric key and algorithm.
     *
     * @param data The data to decrypt
     * @param key The symmetric key to use for decryption
     * @param algorithm The decryption algorithm to use
     * @returns Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>
     */
    decryptSymmetric(
        data: Uint8Array<ArrayBuffer>,
        key: Uint8Array<ArrayBuffer>,
        algorithm: SymmetricEncryptionAlgorithmParams | PbeAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Generates a symmetric key for the specified encryption algorithm.
     *
     * @param algorithm The encryption algorithm to use
     * @returns The generated symmetric key as a Uint8Array<ArrayBuffer>
     */
    generateSymmetricKey(
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Uint8Array<ArrayBuffer>

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
     * @returns Promise resolving to the derived key as a Uint8Array<ArrayBuffer>
     */
    deriveKey(
        password: string | Uint8Array<ArrayBuffer>,
        algorithm: PbeAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>>

    /**
     * Gets the EC curve parameters for a given asymmetric encryption algorithm.
     *
     * @param algorithm The asymmetric encryption algorithm parameters
     * @returns EC curve parameters as a Uint8Array<ArrayBuffer> or ObjectIdentifier
     */
    getEcCurveParameters(
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Uint8Array<ArrayBuffer> | ObjectIdentifier

    /**
     * Converts asymmetric encryption algorithm parameters to a signature algorithm identifier.
     *
     * @param algorithm The asymmetric encryption algorithm parameters
     * @returns Signature algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier
     */
    signatureAlgorithm(
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Uint8Array<ArrayBuffer> | AlgorithmIdentifier

    /**
     * Converts a hash algorithm to a digest algorithm identifier.
     *
     * @param algorithm The hash algorithm
     * @returns Digest algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier
     */
    digestAlgorithm(
        algorithm: HashAlgorithm,
    ): Uint8Array<ArrayBuffer> | AlgorithmIdentifier

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
