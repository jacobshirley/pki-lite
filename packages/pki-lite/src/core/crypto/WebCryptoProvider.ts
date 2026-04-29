import {
    AlgorithmIdentifier,
    PSourceAlgorithm,
} from '../../algorithms/AlgorithmIdentifier.js'
import { CCMParameters } from '../../algorithms/CCMParameters.js'
import { GCMParameters } from '../../algorithms/GCMParameters.js'
import { PBES2Params } from '../../pkcs5/PBES2Params.js'
import { PBEParameter } from '../../pkcs5/PBEParameter.js'
import { RSAESOAEPParams } from '../../algorithms/RSAESOAEPParams.js'
import { RSASSAPSSParams } from '../../algorithms/RSASSAPSSParams.js'
import { BMPString } from '../../asn1/BMPString.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import type { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import type { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'
import { UnsupportedCryptoAlgorithmError } from '../errors/UnsupportedCryptoAlgorithmError.js'
import { OIDs } from '../OIDs.js'
import type { Asn1Any, ObjectIdentifierString } from '../PkiBase.js'
import type {
    AsymmetricEncryptionAlgorithmParams,
    CryptoProvider,
    DerivationAlgorithmParams,
    HashAlgorithm,
    SymmetricEncryptionAlgorithmParams,
    NamedCurve,
    PbeAlgorithmParams,
} from './types.js'
import { PBKDF2Params } from '../../pkcs5/PBKDF2Params.js'
import { pkcs12Derive } from './utils.js'

/**
 * Cryptographic provider implementation using the Web Crypto API.
 *
 * This provider leverages the browser's native Web Crypto API for cryptographic
 * operations, offering excellent performance and security. It supports modern
 * algorithms including RSA, ECDSA, AES, and SHA hashes. The Web Crypto API is
 * available in both browsers and Node.js (16+), making this provider suitable
 * for cross-platform applications.
 *
 * Supported operations:
 * - Hashing: SHA-1, SHA-256, SHA-384, SHA-512 (MD5 not supported)
 * - Asymmetric: RSA-PKCS1, RSA-PSS, RSA-OAEP, ECDSA, ECDH
 * - Symmetric: AES-GCM, AES-CBC, AES-CTR
 * - Key derivation: PBKDF2, HKDF
 *
 * @example
 * ```typescript
 * const provider = new WebCryptoProvider()
 *
 * // Hash data
 * const hash = await provider.digest(data, 'SHA-256')
 *
 * // Sign data with RSA-PSS
 * const signature = await provider.sign(
 *     data,
 *     privateKeyInfo,
 *     { type: 'RSA_PSS', params: { hash: 'SHA-256', saltLength: 32 } }
 * )
 *
 * // Encrypt with AES-GCM
 * const encrypted = await provider.encryptSymmetric(
 *     plaintext,
 *     key,
 *     { type: 'AES_GCM', params: { iv: iv, tagLength: 16 } }
 * )
 * ```
 */
export class WebCryptoProvider implements CryptoProvider {
    /**
     * Reference to the Web Crypto API interface.
     * Protected to allow testing with mock implementations.
     */
    protected crypto: { subtle: SubtleCrypto } = globalThis.crypto

    /**
     * Computes a cryptographic hash of the input data.
     *
     * @param data The data to hash
     * @param algorithm The hash algorithm to use
     * @returns The computed hash bytes
     * @throws UnsupportedCryptoAlgorithmError if the algorithm is not supported
     */
    async digest(
        data: Uint8Array<ArrayBuffer>,
        algorithm: HashAlgorithm,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (algorithm === 'MD5') {
            throw new UnsupportedCryptoAlgorithmError(
                'MD5 is not supported in WebCrypto',
            )
        }
        const hash = await this.crypto.subtle.digest(algorithm, data)
        return new Uint8Array(hash)
    }

    /**
     * Computes an HMAC (Hash-based Message Authentication Code) of the input data.
     *
     * @param key The secret key for HMAC
     * @param data The data to authenticate
     * @param hash The hash algorithm to use
     * @returns The computed HMAC bytes
     * @throws UnsupportedCryptoAlgorithmError if the algorithm is not supported
     */
    async hmac(
        key: Uint8Array<ArrayBuffer>,
        data: Uint8Array<ArrayBuffer>,
        hash: HashAlgorithm,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (hash === 'MD5') {
            throw new UnsupportedCryptoAlgorithmError(
                'MD5 is not supported in WebCrypto',
            )
        }
        const cryptoKey = await this.crypto.subtle.importKey(
            'raw',
            key,
            { name: 'HMAC', hash: { name: hash } },
            false,
            ['sign'],
        )
        const signature = await this.crypto.subtle.sign('HMAC', cryptoKey, data)
        return new Uint8Array(signature)
    }

    /**
     * Converts PKI algorithm parameters to Web Crypto API algorithm specification.
     *
     * @param algorithm The PKI algorithm parameters
     * @returns Web Crypto API compatible algorithm specification
     * @internal
     */
    getWebCryptoAlgorithm(
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ):
        | RsaPssParams
        | EcKeyImportParams
        | RsaOaepParams
        | RsaHashedKeyAlgorithm {
        switch (algorithm.type) {
            case 'RSA_PSS':
                return {
                    name: 'RSA-PSS',
                    hash: { name: algorithm.params.hash },
                    saltLength: algorithm.params.saltLength,
                }
            case 'RSA_OAEP':
                return {
                    name: 'RSA-OAEP',
                    hash: { name: algorithm.params.hash },
                    ...(algorithm.params.label
                        ? { label: algorithm.params.label }
                        : {}),
                }
            case 'RSASSA_PKCS1_v1_5':
                return {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: { name: algorithm.params.hash },
                }
            case 'ECDSA':
                return {
                    name: 'ECDSA',
                    hash: { name: algorithm.params.hash },
                    namedCurve: algorithm.params.namedCurve,
                }
            case 'ECDH':
                return {
                    name: 'ECDH',
                    namedCurve: algorithm.params.namedCurve,
                }
            default:
                const _exhaustiveCheck: never = algorithm
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported algorithm type: ${_exhaustiveCheck}`,
                )
        }
    }

    async sign(
        data: Uint8Array<ArrayBuffer>,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        const webCryptoParams = this.getWebCryptoAlgorithm(algorithm)

        const importedRsaKey = await this.crypto.subtle.importKey(
            'pkcs8',
            privateKeyInfo.toDer(),
            webCryptoParams,
            false,
            ['sign'],
        )

        const signature = await this.crypto.subtle.sign(
            webCryptoParams,
            importedRsaKey,
            data,
        )

        return new Uint8Array(signature)
    }

    async verify(
        data: Uint8Array<ArrayBuffer>,
        publicKeyInfo: SubjectPublicKeyInfo,
        signature: Uint8Array<ArrayBuffer>,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<boolean> {
        const webCryptoParams = this.getWebCryptoAlgorithm(algorithm)
        if (!webCryptoParams) {
            throw new UnsupportedCryptoAlgorithmError(
                `Unsupported algorithm: ${algorithm.type}`,
            )
        }

        const importedKey = await this.crypto.subtle.importKey(
            'spki',
            publicKeyInfo.toDer(),
            webCryptoParams,
            false,
            ['verify'],
        )

        const valid = await this.crypto.subtle.verify(
            webCryptoParams,
            importedKey,
            signature,
            data,
        )

        return valid
    }

    getWebCryptoSymmetricAlgorithm(
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): AesCbcParams | AesGcmParams {
        switch (algorithm.type) {
            case 'AES_128_CBC':
            case 'AES_192_CBC':
            case 'AES_256_CBC': {
                if (algorithm.params.disablePadding) {
                    throw new UnsupportedCryptoAlgorithmError(
                        'AES-CBC with no padding is not supported in WebCrypto',
                    )
                }
                const iv = algorithm.params.nonce
                if (!iv) {
                    throw new UnsupportedCryptoAlgorithmError(
                        `Invalid IV for AES-CBC: ${algorithm.params}`,
                    )
                }
                return { name: 'AES-CBC', iv }
            }

            case 'AES_128_GCM':
            case 'AES_192_GCM':
            case 'AES_256_GCM': {
                const gcmParams = algorithm.params
                if (!gcmParams.nonce) {
                    throw new UnsupportedCryptoAlgorithmError(
                        `Invalid IV for AES-GCM: ${algorithm.params}`,
                    )
                }
                return {
                    name: 'AES-GCM',
                    iv: gcmParams.nonce,
                    tagLength: gcmParams.icvLen ?? 128,
                }
            }

            case 'AES_128_CCM':
            case 'AES_192_CCM':
            case 'AES_256_CCM': {
                const ccmParams = algorithm.params
                if (!ccmParams.nonce) {
                    throw new UnsupportedCryptoAlgorithmError(
                        `Invalid nonce for AES-CCM: ${algorithm.params}`,
                    )
                }
                return {
                    name: 'AES-CCM',
                    iv: ccmParams.nonce,
                    tagLength: ccmParams.icvLen || 128,
                }
            }
            case 'AES_128_ECB':
            case 'AES_192_ECB':
            case 'AES_256_ECB':
                throw new UnsupportedCryptoAlgorithmError(
                    'ECB mode is not supported by WebCryptoProvider. Use an extended crypto provider that supports legacy algorithms.',
                )
            case 'PBES2':
                throw new UnsupportedCryptoAlgorithmError(
                    'PBES2 is not supported for symmetric encryption in WebCrypto. Use an extended crypto provider that supports legacy algorithms.',
                )
            case 'PKCS12_SHA1_3DES_2KEY':
            case 'PKCS12_SHA1_3DES_3KEY':
            case 'PKCS12_SHA1_RC2_128':
            case 'PKCS12_SHA1_RC2_40':
            case 'PKCS12_SHA1_RC4_128':
            case 'PKCS12_SHA1_RC4_40':
                throw new UnsupportedCryptoAlgorithmError(
                    `PKCS#12 PBE algorithm ${algorithm.type} is not supported by WebCryptoProvider. Use an extended crypto provider that supports legacy algorithms.`,
                )

            default:
                const _exhaustiveCheck1: never = algorithm
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric encryption algorithm: ${_exhaustiveCheck1}`,
                )
        }
    }

    getWebCryptoSymmetricKeyGenAlgorithm(
        algorithm: SymmetricEncryptionAlgorithmParams['type'],
    ): AesDerivedKeyParams {
        let name: 'AES-CBC' | 'AES-GCM' | 'AES-CCM' | 'AES-CTR'
        let length: 128 | 192 | 256 = 128
        if (algorithm.includes('128')) {
            length = 128
        } else if (algorithm.includes('192')) {
            length = 192
        } else if (algorithm.includes('256')) {
            length = 256
        } else {
            throw new UnsupportedCryptoAlgorithmError(
                `Unsupported symmetric encryption algorithm: ${algorithm}`,
            )
        }

        switch (algorithm) {
            case 'AES_128_CBC':
            case 'AES_192_CBC':
            case 'AES_256_CBC':
                name = 'AES-CBC'
                break
            case 'AES_128_CCM':
            case 'AES_192_CCM':
            case 'AES_256_CCM':
                name = 'AES-CCM'
                break
            case 'AES_128_GCM':
            case 'AES_192_GCM':
            case 'AES_256_GCM':
                name = 'AES-GCM'
                break
            case 'AES_128_ECB':
            case 'AES_192_ECB':
            case 'AES_256_ECB':
                throw new UnsupportedCryptoAlgorithmError(
                    'ECB mode is not supported by WebCryptoProvider. Use an extended crypto provider that supports legacy algorithms.',
                )
            case 'PBES2':
                throw new UnsupportedCryptoAlgorithmError(
                    'PBES2 is not supported for key generation in WebCryptoProvider. Use an extended crypto provider that supports legacy algorithms.',
                )
            case 'PKCS12_SHA1_RC4_128':
            case 'PKCS12_SHA1_RC4_40':
            case 'PKCS12_SHA1_3DES_3KEY':
            case 'PKCS12_SHA1_3DES_2KEY':
            case 'PKCS12_SHA1_RC2_128':
            case 'PKCS12_SHA1_RC2_40':
                throw new UnsupportedCryptoAlgorithmError(
                    `PKCS#12 PBE algorithm ${algorithm} is not supported by WebCryptoProvider`,
                )

            default:
                const _exhaustiveCheck2: never = algorithm
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric encryption algorithm: ${_exhaustiveCheck2}`,
                )
        }

        return { name, length }
    }

    getWebCryptoDerivationAlgorithm(
        algorithm: DerivationAlgorithmParams,
    ): Pbkdf2Params {
        switch (algorithm.type) {
            case 'PBKDF2':
                return {
                    name: 'PBKDF2',
                    hash: { name: algorithm.params.hash || 'SHA-1' },
                    salt: algorithm.params.salt,
                    iterations: algorithm.params.iterationCount,
                }
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported key derivation algorithm: ${algorithm.type}`,
                )
        }
    }

    getRandomValues(length: number): Uint8Array<ArrayBuffer> {
        return crypto.getRandomValues(new Uint8Array(length))
    }

    protected async getKeyMaterial(
        password: string | Uint8Array<ArrayBuffer>,
    ): Promise<CryptoKey> {
        const enc = new TextEncoder()
        if (typeof password === 'string') {
            password = enc.encode(password)
        }

        const keyMaterial = await this.crypto.subtle.importKey(
            'raw',
            password,
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey'],
        )

        return keyMaterial
    }

    protected async deriveCryptoKey(
        password: string | Uint8Array<ArrayBuffer> | CryptoKey,
        algorithm: PbeAlgorithmParams,
    ): Promise<CryptoKey> {
        if (password instanceof CryptoKey) {
            return password
        }

        // PKCS#12 PBE algorithms are not supported by Web Crypto API
        if (algorithm.type !== 'PBES2') {
            throw new UnsupportedCryptoAlgorithmError(
                `PKCS#12 PBE algorithm ${algorithm.type} is not supported by WebCryptoProvider. Use an extended crypto provider that supports legacy algorithms.`,
            )
        }

        const { derivationAlgorithm } = algorithm.params
        const keyMaterial = await this.getKeyMaterial(password)
        const webCryptoDerivationAlgorithm =
            this.getWebCryptoDerivationAlgorithm(derivationAlgorithm)

        const encryptionAlgorithmParams =
            this.getWebCryptoSymmetricKeyGenAlgorithm(
                algorithm.params.encryptionAlgorithm.type,
            )

        const derivedKey = await this.crypto.subtle.deriveKey(
            webCryptoDerivationAlgorithm,
            keyMaterial,
            encryptionAlgorithmParams,
            false,
            ['encrypt', 'decrypt'],
        )

        return derivedKey
    }

    /**
     * Derives key material using PKCS#12 password-based KDF (RFC 7292 Appendix B).
     * Supports modern hash algorithms for improved security while maintaining OpenSSL compatibility.
     *
     * @param password The password (string or bytes, will be converted to BMPString format)
     * @param salt Salt value for key derivation
     * @param iterationCount Number of iterations for key strengthening
     * @param keyLength Desired key length in bytes
     * @param purpose Key purpose: 'encryption' (id=1), 'iv' (id=2), or 'mac' (id=3)
     * @param hash Hash algorithm to use (default: SHA-1 for legacy compatibility)
     * @returns Promise resolving to the derived key bytes
     *
     * @example
     * ```typescript
     * // Derive a MAC key with SHA-256
     * const macKey = await provider.derivePkcs12Key(
     *     password,
     *     salt,
     *     100000,
     *     32,
     *     'mac',
     *     'SHA-256'
     * )
     * ```
     */
    async derivePkcs12Key(
        password: string | Uint8Array<ArrayBuffer>,
        salt: Uint8Array<ArrayBuffer>,
        iterationCount: number,
        keyLength: number,
        purpose: 'encryption' | 'iv' | 'mac' = 'encryption',
        hash: HashAlgorithm = 'SHA-1',
    ): Promise<Uint8Array<ArrayBuffer>> {
        // Convert password to BMPString format (UTF-16BE with NUL terminator)
        const passwordBytes = BMPString.nullTerminated(password)

        // Map purpose to PKCS#12 id parameter
        const id = purpose === 'encryption' ? 1 : purpose === 'iv' ? 2 : 3

        return pkcs12Derive(
            passwordBytes,
            salt,
            id,
            iterationCount,
            keyLength,
            hash,
        )
    }

    async deriveKey(
        password: string | Uint8Array<ArrayBuffer> | CryptoKey,
        algorithm: PbeAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        // Handle PKCS#12 PBE algorithms using derivePkcs12Key
        if (algorithm.type !== 'PBES2') {
            if (password instanceof CryptoKey) {
                throw new UnsupportedCryptoAlgorithmError(
                    `PKCS#12 PBE algorithm ${algorithm.type} requires a password, not a CryptoKey`,
                )
            }

            const { salt, iterationCount } = algorithm.params

            // Determine key length based on algorithm
            let keyLength: number
            switch (algorithm.type) {
                case 'PKCS12_SHA1_RC4_128':
                case 'PKCS12_SHA1_3DES_2KEY':
                case 'PKCS12_SHA1_RC2_128':
                    keyLength = 16 // 128 bits
                    break
                case 'PKCS12_SHA1_RC4_40':
                case 'PKCS12_SHA1_RC2_40':
                    keyLength = 5 // 40 bits
                    break
                case 'PKCS12_SHA1_3DES_3KEY':
                    keyLength = 24 // 192 bits
                    break
                default:
                    // This should never happen if all PKCS#12 algorithms are handled
                    throw new UnsupportedCryptoAlgorithmError(
                        `Unsupported PKCS#12 PBE algorithm: ${(algorithm as any).type}`,
                    )
            }

            // Legacy PKCS#12 algorithms always use SHA-1
            return this.derivePkcs12Key(
                password,
                salt,
                iterationCount,
                keyLength,
                'encryption',
                'SHA-1',
            )
        }

        // Handle PBES2 using Web Crypto API
        const cryptoKey = await this.deriveCryptoKey(password, algorithm)
        const rawKey = await this.crypto.subtle.exportKey('raw', cryptoKey)
        return new Uint8Array(rawKey)
    }

    async encryptSymmetric(
        data: Uint8Array<ArrayBuffer>,
        key: Uint8Array<ArrayBuffer> | CryptoKey | string,
        algorithm: SymmetricEncryptionAlgorithmParams | PbeAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (algorithm.type === 'PBES2') {
            const derivedKey = await this.deriveCryptoKey(key, algorithm)

            return this.encryptSymmetric(
                data,
                derivedKey,
                algorithm.params.encryptionAlgorithm,
            )
        } else {
            const params = this.getWebCryptoSymmetricAlgorithm(algorithm)
            if (!params)
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric encryption algorithm: ${algorithm}`,
                )

            const cryptoKey =
                key instanceof CryptoKey
                    ? key
                    : await this.crypto.subtle.importKey(
                          'raw',
                          typeof key === 'string'
                              ? new TextEncoder().encode(key)
                              : key,
                          params,
                          false,
                          ['encrypt'],
                      )

            return new Uint8Array(
                await this.crypto.subtle.encrypt(params, cryptoKey, data),
            )
        }
    }

    async encrypt(
        data: Uint8Array<ArrayBuffer>,
        publicKeyInfo: SubjectPublicKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        const params = this.getWebCryptoAlgorithm(algorithm)
        if (!params)
            throw new UnsupportedCryptoAlgorithmError(
                `Unsupported asymmetric encryption algorithm: ${algorithm}`,
            )

        const cryptoKey = await this.crypto.subtle.importKey(
            'spki',
            publicKeyInfo.toDer(),
            params,
            false,
            ['encrypt'],
        )

        return new Uint8Array(
            await this.crypto.subtle.encrypt(params, cryptoKey, data),
        )
    }

    async decrypt(
        data: Uint8Array<ArrayBuffer>,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        const params = this.getWebCryptoAlgorithm(algorithm)

        const cryptoKey = await this.crypto.subtle.importKey(
            'pkcs8',
            privateKeyInfo.toDer(),
            params,
            false,
            ['decrypt'],
        )

        return new Uint8Array(
            await this.crypto.subtle.decrypt(params, cryptoKey, data),
        )
    }

    async decryptSymmetric(
        data: Uint8Array<ArrayBuffer>,
        key: Uint8Array<ArrayBuffer> | CryptoKey | string,
        algorithm: SymmetricEncryptionAlgorithmParams | PbeAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (algorithm.type === 'PBES2') {
            const derivedKey = await this.deriveCryptoKey(key, algorithm)
            return this.decryptSymmetric(
                data,
                derivedKey,
                algorithm.params.encryptionAlgorithm,
            )
        } else {
            const params = this.getWebCryptoSymmetricAlgorithm(algorithm)
            if (!params)
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric decryption algorithm: ${algorithm}`,
                )

            const cryptoKey =
                key instanceof CryptoKey
                    ? key
                    : await this.crypto.subtle.importKey(
                          'raw',
                          typeof key === 'string'
                              ? new TextEncoder().encode(key)
                              : key,
                          params,
                          false,
                          ['decrypt'],
                      )

            return new Uint8Array(
                await this.crypto.subtle.decrypt(params, cryptoKey, data),
            )
        }
    }

    generateSymmetricKey(
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Uint8Array<ArrayBuffer> {
        switch (algorithm.type) {
            case 'AES_128_CBC':
            case 'AES_128_CCM':
            case 'AES_128_GCM':
            case 'AES_128_ECB':
                return this.getRandomValues(16)
            case 'AES_192_CBC':
            case 'AES_192_CCM':
            case 'AES_192_GCM':
            case 'AES_192_ECB':
                return this.getRandomValues(24)
            case 'AES_256_CBC':
            case 'AES_256_CCM':
            case 'AES_256_GCM':
            case 'AES_256_ECB':
                return this.getRandomValues(32)
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric encryption algorithm: ${algorithm}`,
                )
        }
    }

    async generateKeyPair(options: {
        algorithm: 'RSA' | 'EC'
        keySize?: number
        publicExponent?: Uint8Array<ArrayBuffer>
        hash?: string
        namedCurve?: string
    }): Promise<{
        publicKey: Uint8Array<ArrayBuffer>
        privateKey: Uint8Array<ArrayBuffer>
    }> {
        let webCryptoAlgorithm:
            | RsaHashedKeyGenParams
            | EcKeyGenParams
            | AlgorithmIdentifier

        if (options.algorithm === 'RSA') {
            const modulusLength =
                typeof options.keySize === 'number' ? options.keySize : 2048
            webCryptoAlgorithm = {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength,
                publicExponent:
                    options.publicExponent ?? new Uint8Array([1, 0, 1]), // 65537
                hash: { name: options.hash ?? 'SHA-256' },
            }
        } else if (options.algorithm === 'EC') {
            const namedCurve =
                typeof options.namedCurve === 'string'
                    ? options.namedCurve
                    : 'P-256'
            webCryptoAlgorithm = {
                name: 'ECDSA',
                namedCurve,
            }
        } else {
            throw new UnsupportedCryptoAlgorithmError(
                `Unsupported algorithm: ${options.algorithm}`,
            )
        }

        const keyPair = (await this.crypto.subtle.generateKey(
            webCryptoAlgorithm,
            true,
            ['sign', 'verify'],
        )) as CryptoKeyPair

        const privateKey = await this.crypto.subtle.exportKey(
            'pkcs8',
            keyPair.privateKey,
        )
        const publicKey = await this.crypto.subtle.exportKey(
            'spki',
            keyPair.publicKey,
        )

        return {
            privateKey: new Uint8Array(privateKey),
            publicKey: new Uint8Array(publicKey),
        }
    }

    getEcCurveParameters(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): ObjectIdentifier {
        if (encryptionParams.type === 'ECDSA') {
            switch (encryptionParams.params.namedCurve) {
                case 'P-256':
                    return new ObjectIdentifier({
                        value: OIDs.CURVES.SECP256R1,
                    })
                case 'P-384':
                    return new ObjectIdentifier({
                        value: OIDs.CURVES.SECP384R1,
                    })
                case 'P-521':
                    return new ObjectIdentifier({
                        value: OIDs.CURVES.SECP521R1,
                    })
                default:
                    throw new UnsupportedCryptoAlgorithmError(
                        `Unsupported named curve: ${encryptionParams.params.namedCurve}`,
                    )
            }
        }

        throw new UnsupportedCryptoAlgorithmError(
            `Unsupported encryption parameters: ${JSON.stringify(encryptionParams)}`,
        )
    }

    signatureAlgorithm(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): AlgorithmIdentifier {
        if (encryptionParams.type === 'ECDH') {
            throw new Error(`ECDH is not a signature algorithm`)
        }

        const digestAlgorithm = this.digestAlgorithm(
            encryptionParams.params.hash,
        )

        if (encryptionParams.type === 'RSA_OAEP') {
            // Create MGF1 parameters with the same hash algorithm
            const mgf1WithSameHash = new AlgorithmIdentifier({
                algorithm: OIDs.RSA.MGF1,
                parameters: digestAlgorithm,
            })

            // Create pSourceAlgorithm if label is provided
            let pSourceAlgorithm: AlgorithmIdentifier | undefined = undefined
            if (encryptionParams.params.label) {
                pSourceAlgorithm = new PSourceAlgorithm({
                    parameters: new OctetString({
                        bytes: encryptionParams.params.label,
                    }),
                })
            } else if (encryptionParams.params.pSourceAlgorithm) {
                // If a custom pSourceAlgorithm OID is provided, use it with empty parameters
                pSourceAlgorithm = new PSourceAlgorithm({})
            }

            return new AlgorithmIdentifier({
                algorithm: OIDs.RSA.RSAES_OAEP,
                parameters: new RSAESOAEPParams({
                    hashAlgorithm: digestAlgorithm,
                    maskGenAlgorithm: mgf1WithSameHash,
                    pSourceAlgorithm: pSourceAlgorithm,
                }),
            })
        } else if (encryptionParams.type === 'RSA_PSS') {
            // Create MGF1 parameters with the same hash algorithm
            const mgf1WithSameHash = new AlgorithmIdentifier({
                algorithm: OIDs.RSA.MGF1,
                parameters: digestAlgorithm,
            })

            return new AlgorithmIdentifier({
                algorithm: OIDs.RSA.RSASSA_PSS,
                parameters: new RSASSAPSSParams({
                    hashAlgorithm: digestAlgorithm,
                    maskGenAlgorithm: mgf1WithSameHash,
                    saltLength: encryptionParams.params.saltLength,
                }),
            })
        }

        const key: `${AsymmetricEncryptionAlgorithmParams['type']}/${HashAlgorithm}` = `${encryptionParams.type}/${encryptionParams.params.hash}`
        switch (key) {
            case `RSASSA_PKCS1_v1_5/SHA-1`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.RSA.SHA1_WITH_RSA,
                    parameters: null,
                })
            case `RSASSA_PKCS1_v1_5/SHA-256`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.RSA.SHA256_WITH_RSA,
                    parameters: null,
                })
            case `RSASSA_PKCS1_v1_5/SHA-384`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.RSA.SHA384_WITH_RSA,
                    parameters: null,
                })
            case `RSASSA_PKCS1_v1_5/SHA-512`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.RSA.SHA512_WITH_RSA,
                    parameters: null,
                })
            case `ECDSA/SHA-1`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.EC.SHA1_WITH_ECDSA,
                    parameters: this.getEcCurveParameters(encryptionParams),
                })
            case `ECDSA/SHA-256`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.EC.SHA256_WITH_ECDSA,
                    parameters: this.getEcCurveParameters(encryptionParams),
                })
            case `ECDSA/SHA-384`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.EC.SHA384_WITH_ECDSA,
                    parameters: this.getEcCurveParameters(encryptionParams),
                })
            case `ECDSA/SHA-512`:
                return new AlgorithmIdentifier({
                    algorithm: OIDs.EC.SHA512_WITH_ECDSA,
                    parameters: this.getEcCurveParameters(encryptionParams),
                })
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported signature algorithm: ${key}`,
                )
        }
    }

    digestAlgorithm(hash: HashAlgorithm): AlgorithmIdentifier {
        switch (hash) {
            case 'SHA-1':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.HASH.SHA1,
                })
            case 'SHA-256':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.HASH.SHA256,
                })
            case 'SHA-384':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.HASH.SHA384,
                })
            case 'SHA-512':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.HASH.SHA512,
                })
            case 'MD5':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.HASH.MD5,
                })
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported hash algorithm: ${hash}`,
                )
        }
    }

    keyEncryptionAlgorithm(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): AlgorithmIdentifier {
        switch (encryptionParams.type) {
            case 'ECDH':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.EC.ECDH,
                    parameters:
                        AlgorithmIdentifier.getEcCurveParameters(
                            encryptionParams,
                        ),
                })
            default:
                return this.signatureAlgorithm(encryptionParams)
        }
    }

    contentEncryptionAlgorithm(
        encryptionParams:
            | SymmetricEncryptionAlgorithmParams
            | PbeAlgorithmParams,
    ): AlgorithmIdentifier {
        let algorithm: ObjectIdentifierString
        let parameters: Asn1Any | undefined

        switch (encryptionParams.type) {
            case 'AES_128_CBC':
                algorithm = OIDs.ENCRYPTION.AES_128_CBC
                parameters = new OctetString({
                    bytes: encryptionParams.params.nonce,
                })
                break
            case 'AES_192_CBC':
                algorithm = OIDs.ENCRYPTION.AES_192_CBC
                parameters = new OctetString({
                    bytes: encryptionParams.params.nonce,
                })
                break
            case 'AES_256_CBC':
                algorithm = OIDs.ENCRYPTION.AES_256_CBC
                parameters = new OctetString({
                    bytes: encryptionParams.params.nonce,
                })

                break
            case 'AES_128_GCM':
                algorithm = OIDs.ENCRYPTION.AES_128_GCM
                parameters = new GCMParameters({
                    aesNonce: encryptionParams.params.nonce,
                    aesICVlen: encryptionParams.params.icvLen,
                })
                break
            case 'AES_192_GCM':
                algorithm = OIDs.ENCRYPTION.AES_192_GCM
                parameters = new GCMParameters({
                    aesNonce: encryptionParams.params.nonce,
                    aesICVlen: encryptionParams.params.icvLen,
                })
                break
            case 'AES_256_GCM':
                algorithm = OIDs.ENCRYPTION.AES_256_GCM
                parameters = new GCMParameters({
                    aesNonce: encryptionParams.params.nonce,
                    aesICVlen: encryptionParams.params.icvLen,
                })
                break
            case 'AES_128_CCM':
                algorithm = OIDs.ENCRYPTION.AES_128_CCM
                parameters = new CCMParameters({
                    aesNonce: encryptionParams.params.nonce,
                    aesICVlen: encryptionParams.params.icvLen,
                })
                break
            case 'AES_192_CCM':
                algorithm = OIDs.ENCRYPTION.AES_192_CCM
                parameters = new CCMParameters({
                    aesNonce: encryptionParams.params.nonce,
                    aesICVlen: encryptionParams.params.icvLen,
                })
                break
            case 'AES_256_CCM':
                algorithm = OIDs.ENCRYPTION.AES_256_CCM
                parameters = new CCMParameters({
                    aesNonce: encryptionParams.params.nonce,
                    aesICVlen: encryptionParams.params.icvLen,
                })
                break
            case 'AES_128_ECB':
                algorithm = OIDs.ENCRYPTION.AES_128_ECB
                break
            case 'AES_192_ECB':
                algorithm = OIDs.ENCRYPTION.AES_192_ECB
                break
            case 'AES_256_ECB':
                algorithm = OIDs.ENCRYPTION.AES_256_ECB
                break
            case 'PBES2':
                algorithm = OIDs.PKCS5.PBES2
                parameters = new PBES2Params({
                    keyDerivationFunc: new AlgorithmIdentifier({
                        algorithm: OIDs.PKCS5.PBKDF2,
                        parameters: new PBKDF2Params({
                            salt: encryptionParams.params.derivationAlgorithm
                                .params.salt,
                            iterationCount:
                                encryptionParams.params.derivationAlgorithm
                                    .params.iterationCount,
                            keyLength:
                                encryptionParams.params.derivationAlgorithm
                                    .params.keyLength,
                            prf: encryptionParams.params.derivationAlgorithm
                                .params.hash
                                ? this.digestAlgorithm(
                                      encryptionParams.params
                                          .derivationAlgorithm.params.hash,
                                  )
                                : undefined,
                        }),
                    }),
                    encryptionScheme: this.contentEncryptionAlgorithm(
                        encryptionParams.params.encryptionAlgorithm,
                    ),
                })
                break
            case 'PKCS12_SHA1_3DES_2KEY':
            case 'PKCS12_SHA1_3DES_3KEY':
            case 'PKCS12_SHA1_RC2_128':
            case 'PKCS12_SHA1_RC2_40':
            case 'PKCS12_SHA1_RC4_128':
            case 'PKCS12_SHA1_RC4_40':
                throw new UnsupportedCryptoAlgorithmError(
                    `PKCS#12 PBE algorithm ${encryptionParams.type} is not supported by WebCryptoProvider. Use an extended crypto provider that supports legacy algorithms.`,
                )
            default:
                const _exhaustiveCheck: never = encryptionParams
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric encryption algorithm: ${_exhaustiveCheck}. Use an extended crypto provider that supports legacy algorithms.`,
                )
        }

        const contentEncAlg = new AlgorithmIdentifier({
            algorithm,
            parameters,
        })

        return contentEncAlg
    }

    toDerivationAlgorithmParams(
        algorithm: AlgorithmIdentifier,
    ): DerivationAlgorithmParams {
        switch (algorithm.algorithm.toString()) {
            case OIDs.PKCS5.PBKDF2: {
                const params = algorithm.parameters?.parseAs(PBKDF2Params)
                if (!params) {
                    throw new Error(
                        `Invalid PBKDF2 parameters: ${algorithm.parameters}`,
                    )
                }

                if (!(params.salt instanceof OctetString)) {
                    throw new Error(
                        `Unsupported PBKDF2 salt type: ${params.salt}`,
                    )
                }

                return {
                    type: 'PBKDF2',
                    params: {
                        salt: params.salt.bytes,
                        iterationCount: params.iterationCount,
                        keyLength: params.keyLength,
                        hash: params.prf?.toHashAlgorithm() || 'SHA-1',
                    },
                }
            }
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported key derivation algorithm: ${algorithm.friendlyName}`,
                )
        }
    }

    toPbeAlgorithmParams(algorithm: AlgorithmIdentifier): PbeAlgorithmParams {
        const oidString = algorithm.algorithm.toString()

        switch (oidString) {
            case OIDs.PKCS5.PBES2: {
                const parameters = algorithm.parameters?.parseAs(PBES2Params)
                if (!parameters) {
                    throw new Error(
                        `Invalid PBES2 parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PBES2',
                    params: {
                        derivationAlgorithm: this.toDerivationAlgorithmParams(
                            parameters.keyDerivationFunc,
                        ),
                        encryptionAlgorithm:
                            this.toSymmetricEncryptionAlgorithmParams(
                                parameters.encryptionScheme,
                            ),
                    },
                }
            }

            // PKCS#12 PBE algorithms
            case OIDs.PKCS12.PBE.SHA1_RC4_128: {
                const parameters = algorithm.parameters?.parseAs(PBEParameter)
                if (!parameters) {
                    throw new Error(
                        `Invalid PKCS#12 PBE parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PKCS12_SHA1_RC4_128',
                    params: {
                        salt: parameters.salt.bytes,
                        iterationCount: parameters.iterationCount,
                    },
                }
            }

            case OIDs.PKCS12.PBE.SHA1_RC4_40: {
                const parameters = algorithm.parameters?.parseAs(PBEParameter)
                if (!parameters) {
                    throw new Error(
                        `Invalid PKCS#12 PBE parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PKCS12_SHA1_RC4_40',
                    params: {
                        salt: parameters.salt.bytes,
                        iterationCount: parameters.iterationCount,
                    },
                }
            }

            case OIDs.PKCS12.PBE.SHA1_3DES_3KEY_CBC: {
                const parameters = algorithm.parameters?.parseAs(PBEParameter)
                if (!parameters) {
                    throw new Error(
                        `Invalid PKCS#12 PBE parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PKCS12_SHA1_3DES_3KEY',
                    params: {
                        salt: parameters.salt.bytes,
                        iterationCount: parameters.iterationCount,
                    },
                }
            }

            case OIDs.PKCS12.PBE.SHA1_3DES_2KEY_CBC: {
                const parameters = algorithm.parameters?.parseAs(PBEParameter)
                if (!parameters) {
                    throw new Error(
                        `Invalid PKCS#12 PBE parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PKCS12_SHA1_3DES_2KEY',
                    params: {
                        salt: parameters.salt.bytes,
                        iterationCount: parameters.iterationCount,
                    },
                }
            }

            case OIDs.PKCS12.PBE.SHA1_RC2_128_CBC: {
                const parameters = algorithm.parameters?.parseAs(PBEParameter)
                if (!parameters) {
                    throw new Error(
                        `Invalid PKCS#12 PBE parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PKCS12_SHA1_RC2_128',
                    params: {
                        salt: parameters.salt.bytes,
                        iterationCount: parameters.iterationCount,
                    },
                }
            }

            case OIDs.PKCS12.PBE.SHA1_RC2_40_CBC: {
                const parameters = algorithm.parameters?.parseAs(PBEParameter)
                if (!parameters) {
                    throw new Error(
                        `Invalid PKCS#12 PBE parameters: ${algorithm.parameters}`,
                    )
                }
                return {
                    type: 'PKCS12_SHA1_RC2_40',
                    params: {
                        salt: parameters.salt.bytes,
                        iterationCount: parameters.iterationCount,
                    },
                }
            }

            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported PBE algorithm: ${algorithm.friendlyName}`,
                )
        }
    }

    toSymmetricEncryptionAlgorithmParams(
        algorithm: AlgorithmIdentifier,
    ): SymmetricEncryptionAlgorithmParams {
        let type: SymmetricEncryptionAlgorithmParams['type']

        switch (algorithm.algorithm.toString()) {
            case OIDs.ENCRYPTION.AES_128_CBC:
                type = 'AES_128_CBC'
            case OIDs.ENCRYPTION.AES_192_CBC:
                type = 'AES_192_CBC'
            case OIDs.ENCRYPTION.AES_256_CBC: {
                type = 'AES_256_CBC'
                const iv = algorithm.parameters?.parseAs(OctetString)?.bytes
                if (!iv) {
                    throw new Error(
                        `Invalid IV for AES-CBC: ${algorithm.parameters}`,
                    )
                }

                return {
                    type,
                    params: { nonce: iv, disablePadding: false },
                }
            }

            case OIDs.ENCRYPTION.AES_128_GCM:
                type = 'AES_128_GCM'
            case OIDs.ENCRYPTION.AES_192_GCM:
                type = 'AES_192_GCM'
            case OIDs.ENCRYPTION.AES_256_GCM: {
                type = 'AES_256_GCM'
                const gcmParams = algorithm.parameters?.parseAs(GCMParameters)
                if (!gcmParams) {
                    throw new Error(
                        `Invalid GCM parameters for AES-GCM: ${algorithm.parameters}`,
                    )
                }
                const tagLength = gcmParams.aesICVlen.get()

                return {
                    type,
                    params: {
                        nonce: gcmParams.aesNonce.bytes,
                        icvLen: tagLength ? tagLength * 8 : undefined, // Convert to bits
                    },
                }
            }

            case OIDs.ENCRYPTION.AES_128_CCM:
                type = 'AES_128_CCM'
            case OIDs.ENCRYPTION.AES_192_CCM:
                type = 'AES_192_CCM'
            case OIDs.ENCRYPTION.AES_256_CCM: {
                type = 'AES_256_CCM'
                const ccmParams = algorithm.parameters?.parseAs(CCMParameters)
                if (!ccmParams) {
                    throw new Error(
                        `Invalid CCM parameters for AES-CCM: ${algorithm.parameters}`,
                    )
                }
                const tagLength = ccmParams.aesICVlen.get()
                return {
                    type,
                    params: {
                        nonce: ccmParams.aesNonce.bytes,
                        icvLen: tagLength ? tagLength * 8 : undefined, // Convert to bits
                    },
                }
            }
            case OIDs.ENCRYPTION.AES_128_ECB:
                type = 'AES_128_ECB'
            case OIDs.ENCRYPTION.AES_192_ECB:
                type = 'AES_192_ECB'
            case OIDs.ENCRYPTION.AES_256_ECB: {
                type = 'AES_256_ECB'
                return {
                    type,
                    params: {
                        disablePadding: false,
                    },
                }
            }
            case OIDs.PKCS5.PBES2:
                return this.toPbeAlgorithmParams(algorithm)

            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported symmetric encryption algorithm: ${algorithm.friendlyName}`,
                )
        }
    }

    toAsymmetricEncryptionAlgorithmParams(
        algorithm: AlgorithmIdentifier,
        publicKeyInfo?: SubjectPublicKeyInfo,
    ): AsymmetricEncryptionAlgorithmParams {
        // Map known algorithm OIDs to their parameters
        switch (algorithm.algorithm.value) {
            case OIDs.RSA.RSASSA_PSS:
                if (!algorithm.parameters) {
                    throw new Error('RSASSA-PSS requires parameters')
                }

                const rassParams = RSASSAPSSParams.fromAsn1(
                    algorithm.parameters.toAsn1(),
                )

                return {
                    type: 'RSA_PSS',
                    params: {
                        hash: this.toHashAlgorithm(
                            rassParams.getEffectiveHashAlgorithm(),
                        ),
                        saltLength: rassParams.getEffectiveSaltLength(),
                    },
                }

            case OIDs.RSA.RSAES_OAEP:
                if (!algorithm.parameters) {
                    throw new Error('RSAES-OAEP requires parameters')
                }

                const oaepParams = RSAESOAEPParams.fromAsn1(
                    algorithm.parameters.toAsn1(),
                )

                const labelBytes = oaepParams.pSourceAlgorithm?.getLabelBytes()
                return {
                    type: 'RSA_OAEP',
                    params: {
                        hash: this.toHashAlgorithm(
                            oaepParams.getEffectiveHashAlgorithm(),
                        ),
                        ...(labelBytes ? { label: labelBytes } : {}),
                        pSourceAlgorithm:
                            oaepParams.pSourceAlgorithm?.algorithm.value,
                    },
                }

            case OIDs.RSA.SHA1_WITH_RSA:
                return {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: { hash: 'SHA-1' },
                }
            case OIDs.RSA.SHA256_WITH_RSA:
                return {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: { hash: 'SHA-256' },
                }
            case OIDs.RSA.SHA384_WITH_RSA:
                return {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: { hash: 'SHA-384' },
                }
            case OIDs.RSA.SHA512_WITH_RSA:
                return {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: { hash: 'SHA-512' },
                }
            case OIDs.EC.SHA1_WITH_ECDSA:
                return {
                    type: 'ECDSA',
                    params: {
                        hash: 'SHA-1',
                        namedCurve: this.getEcNamedCurve(
                            algorithm,
                            publicKeyInfo,
                        ),
                    },
                }
            case OIDs.EC.SHA256_WITH_ECDSA:
                return {
                    type: 'ECDSA',
                    params: {
                        hash: 'SHA-256',
                        namedCurve: this.getEcNamedCurve(
                            algorithm,
                            publicKeyInfo,
                        ),
                    },
                }

            case OIDs.EC.SHA384_WITH_ECDSA:
                return {
                    type: 'ECDSA',
                    params: {
                        hash: 'SHA-384',
                        namedCurve: this.getEcNamedCurve(
                            algorithm,
                            publicKeyInfo,
                        ),
                    },
                }
            case OIDs.EC.SHA512_WITH_ECDSA:
                return {
                    type: 'ECDSA',
                    params: {
                        hash: 'SHA-512',
                        namedCurve: this.getEcNamedCurve(
                            algorithm,
                            publicKeyInfo,
                        ),
                    },
                }
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported algorithm: ${algorithm.friendlyName}`,
                )
        }
    }

    getEcNamedCurve(
        algorithm: AlgorithmIdentifier,
        publicKeyInfo?: SubjectPublicKeyInfo,
    ): NamedCurve {
        let curve =
            algorithm.parameters?.parseAs(ObjectIdentifier)?.value ??
            publicKeyInfo?.algorithm.parameters?.parseAs(ObjectIdentifier)
                ?.value
        if (!curve) {
            throw new Error('EC curve parameters missing')
        }

        switch (curve) {
            case OIDs.CURVES.SECP256R1:
                return 'P-256'
            case OIDs.CURVES.SECP384R1:
                return 'P-384'
            case OIDs.CURVES.SECP521R1:
                return 'P-521'
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported curve OID: ${curve}`,
                )
        }
    }

    toHashAlgorithm(algorithm: AlgorithmIdentifier): HashAlgorithm {
        switch (algorithm.algorithm.value) {
            case OIDs.HASH.SHA1:
                return 'SHA-1'
            case OIDs.HASH.SHA256:
                return 'SHA-256'
            case OIDs.HASH.SHA384:
                return 'SHA-384'
            case OIDs.HASH.SHA512:
                return 'SHA-512'
            case OIDs.HASH.MD5:
                return 'MD5'
            case OIDs.HASH.HMAC_SHA1:
                return 'SHA-1'
            case OIDs.HASH.HMAC_SHA256:
                return 'SHA-256'
            case OIDs.HASH.HMAC_SHA384:
                return 'SHA-384'
            case OIDs.HASH.HMAC_SHA512:
                return 'SHA-512'
            default:
                throw new UnsupportedCryptoAlgorithmError(
                    `Unsupported hash algorithm: ${algorithm.friendlyName}`,
                )
        }
    }
}
