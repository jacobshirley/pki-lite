import { md5 as _md5 } from '@noble/hashes/legacy.js'
import { ecb, cbc } from '@noble/ciphers/aes.js'
import {
    WebCryptoProvider,
    HashAlgorithm,
    SymmetricEncryptionAlgorithmParams,
    AsymmetricEncryptionAlgorithmParams,
} from 'pki-lite/core/crypto/index.js'
import { SubjectPublicKeyInfo } from 'pki-lite/keys/SubjectPublicKeyInfo'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo'
import forge from 'node-forge'
import { fromForgeBytes, toForgeBytes } from './utils'
import { getPbeAlgorithm } from './pbeAlgorithms'
import { AlgorithmIdentifier } from 'pki-lite/algorithms/AlgorithmIdentifier'
import { OIDs } from 'pki-lite/index'
import { PBEParameter } from './PBEParameter'

export class WebCryptoExtendedProvider extends WebCryptoProvider {
    async digest(
        data: Uint8Array,
        algorithm: HashAlgorithm,
    ): Promise<Uint8Array> {
        if (algorithm === 'MD5') {
            return _md5(data)
        }
        return super.digest(data, algorithm)
    }

    async encryptSymmetric(
        data: Uint8Array,
        key: Uint8Array,
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array> {
        if (
            (algorithm.type === 'AES_128_CBC' ||
                algorithm.type === 'AES_192_CBC' ||
                algorithm.type === 'AES_256_CBC') &&
            algorithm.params.disablePadding
        ) {
            return cbc(key, algorithm.params.nonce, {
                disablePadding: true,
            }).encrypt(data)
        } else if (
            algorithm.type === 'AES_128_ECB' ||
            algorithm.type === 'AES_192_ECB' ||
            algorithm.type === 'AES_256_ECB'
        ) {
            return ecb(key).encrypt(data)
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
        data: Uint8Array,
        key: Uint8Array,
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array> {
        if (
            (algorithm.type === 'AES_128_CBC' ||
                algorithm.type === 'AES_192_CBC' ||
                algorithm.type === 'AES_256_CBC') &&
            algorithm.params.disablePadding
        ) {
            return cbc(key, algorithm.params.nonce, {
                disablePadding: true,
            }).decrypt(data)
        } else if (
            algorithm.type === 'AES_128_ECB' ||
            algorithm.type === 'AES_192_ECB' ||
            algorithm.type === 'AES_256_ECB'
        ) {
            return ecb(key).decrypt(data)
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
        data: Uint8Array,
        publicKeyInfo: SubjectPublicKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array> {
        if (algorithm.type === 'RSASSA_PKCS1_v1_5') {
            const publicKeyPem = forge.pki.publicKeyFromPem(
                publicKeyInfo.getPublicKey().toPem(),
            )

            const encrypted = publicKeyPem.encrypt(toForgeBytes(data))
            if (!encrypted) {
                throw new Error('Encryption failed')
            }

            return fromForgeBytes(encrypted)
        }

        return super.encrypt(data, publicKeyInfo, algorithm)
    }

    async decrypt(
        data: Uint8Array,
        privateKeyInfo: PrivateKeyInfo,
        algorithm: AsymmetricEncryptionAlgorithmParams,
    ): Promise<Uint8Array> {
        // Currently only RSA-OAEP is supported for asymmetric encryption in WebCrypto
        if (algorithm.type === 'RSASSA_PKCS1_v1_5') {
            const privateKeyPem = forge.pki.privateKeyFromPem(
                privateKeyInfo.getPrivateKey().toPem(),
            )

            const decrypted = privateKeyPem.decrypt(toForgeBytes(data))
            if (!decrypted) {
                throw new Error('Decryption failed')
            }

            return fromForgeBytes(decrypted)
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
}
