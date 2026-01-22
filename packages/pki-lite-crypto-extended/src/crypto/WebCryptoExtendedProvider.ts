import { md5 as _md5 } from '@noble/hashes/legacy.js'
import { ecb, cbc } from '@noble/ciphers/aes.js'
import {
    WebCryptoProvider,
    HashAlgorithm,
    SymmetricEncryptionAlgorithmParams,
    AsymmetricEncryptionAlgorithmParams,
    PbeAlgorithmParams,
} from 'pki-lite/core/crypto/index.js'
import { SubjectPublicKeyInfo } from 'pki-lite/keys/SubjectPublicKeyInfo.js'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import forge from 'node-forge'
import { getPbeAlgorithm } from './pbeAlgorithms.js'
import { AlgorithmIdentifier } from 'pki-lite/algorithms/AlgorithmIdentifier.js'
import { OIDs } from 'pki-lite/core/OIDs.js'
import { PBEParameter } from 'pki-lite/pkcs5/PBEParameter.js'

/**
 * Extended WebCryptoProvider that adds support for additional algorithms
 * such as MD5 hashing, AES ECB mode, and certain PBE algorithms.
 *
 * Note: This implementation uses the 'node-forge' library for RSA encryption/decryption
 * with PKCS#1 v1.5 padding, as WebCrypto does not support this mode directly.
 *
 * Caution: MD5 is considered cryptographically weak and should be used with caution.
 * This provider is intended for compatibility with legacy systems and not for secure applications.
 *
 * @example
 * const provider = new WebCryptoExtendedProvider();
 * const hash = await provider.digest(data, 'MD5');
 * const encrypted = await provider.encryptSymmetric(data, key, { type: 'AES_128_ECB' });
 * const decrypted = await provider.decryptSymmetric(encryptedData, key, { type: 'AES_128_ECB' });
 * const rsaEncrypted = await provider.encrypt(data, publicKeyInfo, { type: 'RSASSA_PKCS1_v1_5' });
 * const rsaDecrypted = await provider.decrypt(rsaEncryptedData, privateKeyInfo, { type: 'RSASSA_PKCS1_v1_5' });
 */
export class WebCryptoExtendedProvider extends WebCryptoProvider {
    async digest(
        data: Uint8Array<ArrayBuffer>,
        algorithm: HashAlgorithm,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (algorithm === 'MD5') {
            return new Uint8Array(_md5(data))
        }
        return super.digest(data, algorithm)
    }

    async encryptSymmetric(
        data: Uint8Array<ArrayBuffer>,
        key: Uint8Array<ArrayBuffer>,
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (
            (algorithm.type === 'AES_128_CBC' ||
                algorithm.type === 'AES_192_CBC' ||
                algorithm.type === 'AES_256_CBC') &&
            algorithm.params.disablePadding
        ) {
            return new Uint8Array(
                cbc(key, algorithm.params.nonce, {
                    disablePadding: true,
                }).encrypt(data),
            )
        } else if (
            algorithm.type === 'AES_128_ECB' ||
            algorithm.type === 'AES_192_ECB' ||
            algorithm.type === 'AES_256_ECB'
        ) {
            return new Uint8Array(ecb(key).encrypt(data))
        } else if (
            algorithm.type === 'SHA1_3DES_2KEY_CBC' ||
            algorithm.type === 'SHA1_RC2_40_CBC' ||
            algorithm.type === 'SHA1_3DES_3KEY_CBC'
        ) {
            const algo = getPbeAlgorithm(algorithm.type)
            return algo.encrypt(
                data,
                key,
                algorithm.params.salt,
                algorithm.params.iterationCount,
            )
        }

        return super.encryptSymmetric(data, key, algorithm)
    }

    async decryptSymmetric(
        data: Uint8Array<ArrayBuffer>,
        key: Uint8Array<ArrayBuffer>,
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (
            (algorithm.type === 'AES_128_CBC' ||
                algorithm.type === 'AES_192_CBC' ||
                algorithm.type === 'AES_256_CBC') &&
            algorithm.params.disablePadding
        ) {
            return new Uint8Array(
                cbc(key, algorithm.params.nonce, {
                    disablePadding: true,
                }).decrypt(data),
            )
        } else if (
            algorithm.type === 'AES_128_ECB' ||
            algorithm.type === 'AES_192_ECB' ||
            algorithm.type === 'AES_256_ECB'
        ) {
            return new Uint8Array(ecb(key).decrypt(data))
        } else if (
            algorithm.type === 'SHA1_3DES_2KEY_CBC' ||
            algorithm.type === 'SHA1_RC2_40_CBC' ||
            algorithm.type === 'SHA1_3DES_3KEY_CBC'
        ) {
            const algo = getPbeAlgorithm(algorithm.type)
            return algo.decrypt(
                data,
                key,
                algorithm.params.salt,
                algorithm.params.iterationCount,
            )
        }

        return super.decryptSymmetric(data, key, algorithm)
    }

    async encrypt(
        data: Uint8Array<ArrayBuffer>,
        publicKeyInfo: SubjectPublicKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        if (algorithm.type === 'RSASSA_PKCS1_v1_5') {
            const publicKeyPem = forge.pki.publicKeyFromPem(
                publicKeyInfo.getPublicKey().toPem(),
            )

            const encrypted = publicKeyPem.encrypt(
                forge.util.binary.raw.encode(data),
            )
            if (!encrypted) {
                throw new Error('Encryption failed')
            }

            return new Uint8Array(forge.util.binary.raw.decode(encrypted))
        }

        return super.encrypt(data, publicKeyInfo, algorithm)
    }

    async decrypt(
        data: Uint8Array<ArrayBuffer>,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array<ArrayBuffer>> {
        // Currently only RSA-OAEP is supported for asymmetric encryption in WebCrypto
        if (algorithm.type === 'RSASSA_PKCS1_v1_5') {
            const privateKeyPem = forge.pki.privateKeyFromPem(
                privateKeyInfo.getPrivateKey().toPem(),
            )

            const decrypted = privateKeyPem.decrypt(
                forge.util.binary.raw.encode(data),
            )
            if (!decrypted) {
                throw new Error('Decryption failed')
            }

            return new Uint8Array(forge.util.binary.raw.decode(decrypted))
        }

        return super.decrypt(data, privateKeyInfo, algorithm)
    }

    toSymmetricEncryptionAlgorithmParams(
        algorithm: AlgorithmIdentifier,
    ): SymmetricEncryptionAlgorithmParams {
        switch (algorithm.algorithm.value) {
            case OIDs.PKCS12.PBE.SHA1_3DES_2KEY_CBC: {
                const params = algorithm.parameters?.parseAs(PBEParameter)
                if (!params) {
                    throw new Error('Missing PBE parameters')
                }

                return {
                    type: 'SHA1_3DES_2KEY_CBC',
                    params: {
                        salt: params.salt.bytes,
                        iterationCount: params.iterationCount,
                    },
                }
            }
            case OIDs.PKCS12.PBE.SHA1_RC2_40_CBC: {
                const params = algorithm.parameters?.parseAs(PBEParameter)
                if (!params) {
                    throw new Error('Missing PBE parameters')
                }

                return {
                    type: 'SHA1_RC2_40_CBC',
                    params: {
                        salt: params.salt.bytes,
                        iterationCount: params.iterationCount,
                    },
                }
            }
            case OIDs.PKCS12.PBE.SHA1_3DES_3KEY_CBC: {
                const params = algorithm.parameters?.parseAs(PBEParameter)
                if (!params) {
                    throw new Error('Missing PBE parameters')
                }

                return {
                    type: 'SHA1_3DES_3KEY_CBC',
                    params: {
                        salt: params.salt.bytes,
                        iterationCount: params.iterationCount,
                    },
                }
            }
            default:
                return super.toSymmetricEncryptionAlgorithmParams(algorithm)
        }
    }

    contentEncryptionAlgorithm(
        encryptionParams:
            | SymmetricEncryptionAlgorithmParams
            | PbeAlgorithmParams,
    ): AlgorithmIdentifier {
        switch (encryptionParams.type) {
            case 'SHA1_3DES_2KEY_CBC':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.PKCS12.PBE.SHA1_3DES_2KEY_CBC,
                    parameters: new PBEParameter({
                        salt: encryptionParams.params.salt,
                        iterationCount: encryptionParams.params.iterationCount,
                    }),
                })
            case 'SHA1_RC2_40_CBC':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.PKCS12.PBE.SHA1_RC2_40_CBC,
                    parameters: new PBEParameter({
                        salt: encryptionParams.params.salt,
                        iterationCount: encryptionParams.params.iterationCount,
                    }),
                })
            case 'SHA1_RC2_128_CBC':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.PKCS12.PBE.SHA1_RC2_128_CBC,
                    parameters: new PBEParameter({
                        salt: encryptionParams.params.salt,
                        iterationCount: encryptionParams.params.iterationCount,
                    }),
                })
            case 'SHA1_3DES_3KEY_CBC':
                return new AlgorithmIdentifier({
                    algorithm: OIDs.PKCS12.PBE.SHA1_3DES_3KEY_CBC,
                    parameters: new PBEParameter({
                        salt: encryptionParams.params.salt,
                        iterationCount: encryptionParams.params.iterationCount,
                    }),
                })
            default:
                return super.contentEncryptionAlgorithm(encryptionParams)
        }
    }
}
