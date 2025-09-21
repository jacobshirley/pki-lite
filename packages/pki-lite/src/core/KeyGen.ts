import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { getCryptoProvider } from './crypto/crypto.js'
import { KeyPair, KeyPairGenOptions } from './crypto/types.js'

export class KeyGen {
    /**
     * Generates a new key pair.
     *
     * @param options The key generation options
     * @returns A PrivateKeyInfo containing the generated key pair
     */
    static async generate(options: KeyPairGenOptions): Promise<{
        privateKey: PrivateKeyInfo
        publicKey: SubjectPublicKeyInfo
    }> {
        const keyPair: KeyPair =
            await getCryptoProvider().generateKeyPair(options)

        const privateKey = PrivateKeyInfo.fromDer(keyPair.privateKey)
        const publicKey = SubjectPublicKeyInfo.fromDer(keyPair.publicKey)

        return { privateKey, publicKey }
    }
}
