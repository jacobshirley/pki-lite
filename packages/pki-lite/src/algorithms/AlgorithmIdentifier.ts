import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    ObjectIdentifierString,
    derToAsn1,
} from '../core/PkiBase.js'
import { getOidFriendlyName, OIDs } from '../core/OIDs.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Any } from '../asn1/Any.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    HashAlgorithm,
    SymmetricEncryptionAlgorithmParams,
    NamedCurve,
} from '../core/crypto/types.js'
import { RSASSAPSSParams } from './RSASSAPSSParams.js'
import { RSAESOAEPParams } from './RSAESOAEPParams.js'
import { OctetString } from '../asn1/OctetString.js'
import { getCryptoProvider } from '../core/crypto/crypto.js'
import { GCMParameters } from './GCMParameters.js'
import { CCMParameters } from './CCMParameters.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { BitString } from '../asn1/BitString.js'
import { ECDSASignature } from '../keys/ECDSASignature.js'
import { ECPublicKey } from '../keys/ECPublicKey.js'
import { ECPrivateKey } from '../keys/ECPrivateKey.js'
import { UnsupportedCryptoAlgorithm } from '../core/index.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an algorithm identifier.
 *
 * @asn
 * ```asn
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL
 * }
 * ```
 */
export class AlgorithmIdentifier extends PkiBase<AlgorithmIdentifier> {
    algorithm: ObjectIdentifier
    parameters?: Any
    protected noPadding: boolean = false

    constructor(options: {
        algorithm: ObjectIdentifierString
        parameters?: Asn1Any
    }) {
        super()
        const { algorithm, parameters } = options

        this.algorithm = new ObjectIdentifier({ value: algorithm })
        this.parameters =
            parameters !== undefined
                ? new Any({ derBytes: parameters })
                : undefined
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [this.algorithm.toAsn1()]

        if (this.parameters !== undefined) {
            values.push(this.parameters.toAsn1())
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    get commonAlgorithmName(): string {
        // Use the centralized OID to friendly name mapping
        return getOidFriendlyName(this.algorithm.value)
    }

    /**
     * Creates an AlgorithmIdentifier from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns An AlgorithmIdentifier
     */
    static fromAsn1(asn1: Asn1BaseBlock): AlgorithmIdentifier {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Expected Sequence but got ' + asn1.constructor.name,
            )
        }

        const algorithm = asn1.valueBlock.value[0]
        if (!(algorithm instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Expected ObjectIdentifier for algorithm but got ' +
                    algorithm.constructor.name,
            )
        }

        const algorithmOid = algorithm.valueBlock.toString()

        let parameters: Asn1Any | undefined = undefined
        if (asn1.valueBlock.value.length > 1) {
            const param = asn1.valueBlock.value[1]
            // Convert parameter to appropriate Asn1Any type
            parameters = new Any({ derBytes: param })
        }

        return new AlgorithmIdentifier({ algorithm: algorithmOid, parameters })
    }

    static fromDer(bytes: Uint8Array): AlgorithmIdentifier {
        return AlgorithmIdentifier.fromAsn1(derToAsn1(bytes))
    }

    static randomBytes(length: number): Uint8Array {
        return getCryptoProvider().getRandomValues(length)
    }

    getEcNamedCurve(publicKeyInfo?: SubjectPublicKeyInfo): NamedCurve {
        return getCryptoProvider().getEcNamedCurve(this, publicKeyInfo)
    }

    static digestAlgorithm(params: HashAlgorithm): DigestAlgorithmIdentifier {
        const crypto = getCryptoProvider()
        const algorithm = crypto.digestAlgorithm(params)

        if (algorithm instanceof Uint8Array) {
            return DigestAlgorithmIdentifier.fromDer(algorithm)
        }

        return new DigestAlgorithmIdentifier(algorithm)
    }

    static signatureAlgorithm(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): SignatureAlgorithmIdentifier {
        const crypto = getCryptoProvider()
        const algorithm = crypto.signatureAlgorithm(encryptionParams)

        if (algorithm instanceof Uint8Array) {
            return SignatureAlgorithmIdentifier.fromDer(algorithm)
        }

        return new SignatureAlgorithmIdentifier(algorithm)
    }

    static keyEncryptionAlgorithm(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): KeyEncryptionAlgorithmIdentifier {
        const crypto = getCryptoProvider()
        const algorithm = crypto.signatureAlgorithm(encryptionParams)

        if (algorithm instanceof Uint8Array) {
            return KeyEncryptionAlgorithmIdentifier.fromDer(algorithm)
        }

        return new KeyEncryptionAlgorithmIdentifier(algorithm)
    }

    static contentEncryptionAlgorithm(
        encryptionParams: SymmetricEncryptionAlgorithmParams,
    ): ContentEncryptionAlgorithmIdentifier {
        const crypto = getCryptoProvider()
        const algorithm = crypto.contentEncryptionAlgorithm(encryptionParams)

        let contentEncAlg: ContentEncryptionAlgorithmIdentifier
        if (algorithm instanceof Uint8Array) {
            contentEncAlg =
                ContentEncryptionAlgorithmIdentifier.fromDer(algorithm)
        } else {
            contentEncAlg = new ContentEncryptionAlgorithmIdentifier(algorithm)
        }

        if ('disablePadding' in encryptionParams.params) {
            contentEncAlg.setNoPadding(
                encryptionParams.params.disablePadding ?? false,
            )
        }

        return contentEncAlg
    }

    static getEcCurveParameters(
        encryptionParams: AsymmetricEncryptionAlgorithmParams,
    ): ObjectIdentifier {
        const crypto = getCryptoProvider()
        const objectIdentifier = crypto.getEcCurveParameters(encryptionParams)

        if (objectIdentifier instanceof Uint8Array) {
            return ObjectIdentifier.fromDer(objectIdentifier)
        }

        return objectIdentifier
    }
}

/**
 * Represents a digest algorithm identifier, with a convenience method for hashing data.
 *
 * @asn
 * ```asn
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * ```
 */
export class DigestAlgorithmIdentifier extends AlgorithmIdentifier {
    async digest(data: Uint8Array | PkiBase): Promise<Uint8Array> {
        const crypto = getCryptoProvider()
        return await crypto.digest(
            data instanceof Uint8Array ? data : data.toDer(),
            this.toHashAlgorithm(),
        )
    }

    static fromAsn1(asn1: Asn1BaseBlock): DigestAlgorithmIdentifier {
        const algId = AlgorithmIdentifier.fromAsn1(asn1)
        return new DigestAlgorithmIdentifier({
            algorithm: algId.algorithm.value,
            parameters: algId.parameters,
        })
    }

    static fromDer(bytes: Uint8Array): DigestAlgorithmIdentifier {
        return new DigestAlgorithmIdentifier(AlgorithmIdentifier.fromDer(bytes))
    }

    toHashAlgorithm(): HashAlgorithm {
        return getCryptoProvider().toHashAlgorithm(this)
    }
}

/**
 * Represents a signature algorithm identifier.
 *
 * @asn
 * ```asn
 * SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
 * ```
 */
export class SignatureAlgorithmIdentifier extends AlgorithmIdentifier {
    toAsymmetricEncryptionAlgorithmParams(
        publicKeyInfo?: SubjectPublicKeyInfo,
    ): AsymmetricEncryptionAlgorithmParams {
        return getCryptoProvider().toAsymmetricEncryptionAlgorithmParams(
            this,
            publicKeyInfo,
        )
    }

    async sign(
        data: Uint8Array | PkiBase,
        privateKeyInfo: PrivateKeyInfo,
    ): Promise<Uint8Array> {
        const crypto = getCryptoProvider()
        const signature = await crypto.sign(
            data instanceof Uint8Array ? data : data.toDer(),
            privateKeyInfo,
            this.toAsymmetricEncryptionAlgorithmParams(),
        )

        if (privateKeyInfo.getPrivateKey() instanceof ECPrivateKey) {
            return ECDSASignature.fromRaw(signature).toDer()
        }

        return signature
    }

    async verify(
        data: Uint8Array | PkiBase,
        signature: Uint8Array | PkiBase,
        publicKeyInfo: SubjectPublicKeyInfo,
    ): Promise<boolean> {
        const crypto = getCryptoProvider()

        const signatureBytes =
            signature instanceof Uint8Array
                ? signature
                : signature instanceof BitString
                  ? signature.bytes
                  : signature.toDer()

        signature =
            publicKeyInfo.getPublicKey() instanceof ECPublicKey
                ? ECDSASignature.fromDer(signatureBytes).toRaw()
                : signatureBytes

        return await crypto.verify(
            data instanceof Uint8Array ? data : data.toDer(),
            publicKeyInfo,
            signature,
            this.toAsymmetricEncryptionAlgorithmParams(publicKeyInfo),
        )
    }

    static fromAsn1(asn1: asn1js.BaseBlock): SignatureAlgorithmIdentifier {
        const algId = AlgorithmIdentifier.fromAsn1(asn1)
        return new SignatureAlgorithmIdentifier({
            algorithm: algId.algorithm.value,
            parameters: algId.parameters,
        })
    }

    static fromDer(bytes: Uint8Array): SignatureAlgorithmIdentifier {
        return new SignatureAlgorithmIdentifier(
            AlgorithmIdentifier.fromDer(bytes),
        )
    }
}

/**
 * Represents a key encryption algorithm identifier.
 *
 * @asn
 * ```asn
 * KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * ```
 */
export class KeyEncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
    toAsymmetricEncryptionAlgorithmParams(
        publicKeyInfo?: SubjectPublicKeyInfo,
    ): AsymmetricEncryptionAlgorithmParams {
        return getCryptoProvider().toAsymmetricEncryptionAlgorithmParams(
            this,
            publicKeyInfo,
        )
    }

    async encrypt(
        data: Uint8Array | PkiBase,
        publicKeyInfo: SubjectPublicKeyInfo,
    ): Promise<Uint8Array> {
        const crypto = getCryptoProvider()
        return await crypto.encrypt(
            data instanceof Uint8Array ? data : data.toDer(),
            publicKeyInfo,
            this.toAsymmetricEncryptionAlgorithmParams(publicKeyInfo),
        )
    }

    async decrypt(
        data: Uint8Array | PkiBase,
        privateKeyInfo: PrivateKeyInfo,
    ): Promise<Uint8Array> {
        const crypto = getCryptoProvider()
        return await crypto.decrypt(
            data instanceof Uint8Array ? data : data.toDer(),
            privateKeyInfo,
            this.toAsymmetricEncryptionAlgorithmParams(),
        )
    }

    static fromAsn1(asn1: Asn1BaseBlock): KeyEncryptionAlgorithmIdentifier {
        const algId = AlgorithmIdentifier.fromAsn1(asn1)
        return new KeyEncryptionAlgorithmIdentifier({
            algorithm: algId.algorithm.value,
            parameters: algId.parameters,
        })
    }

    static fromDer(bytes: Uint8Array): KeyEncryptionAlgorithmIdentifier {
        return new KeyEncryptionAlgorithmIdentifier(
            AlgorithmIdentifier.fromDer(bytes),
        )
    }
}

/**
 * Represents a content encryption algorithm identifier.
 *
 * @asn
 * ```asn
 * ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * ```
 */
export class ContentEncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
    toSymmetricEncryptionAlgorithmParams(): SymmetricEncryptionAlgorithmParams {
        const cryptoProvider = getCryptoProvider()
        const params = cryptoProvider.toSymmetricEncryptionAlgorithmParams(this)

        if ('disablePadding' in params.params) {
            params.params.disablePadding = this.noPadding
        }

        return params
    }

    generateKey(): Uint8Array {
        const crypto = getCryptoProvider()
        return crypto.generateSymmetricKey(
            this.toSymmetricEncryptionAlgorithmParams(),
        )
    }

    async encrypt(
        data: Uint8Array | PkiBase,
        key: Uint8Array,
    ): Promise<Uint8Array> {
        const crypto = getCryptoProvider()
        return await crypto.encryptSymmetric(
            data instanceof Uint8Array ? data : data.toDer(),
            key,
            this.toSymmetricEncryptionAlgorithmParams(),
        )
    }

    async decrypt(
        data: Uint8Array | PkiBase,
        key: Uint8Array,
    ): Promise<Uint8Array> {
        const crypto = getCryptoProvider()
        return await crypto.decryptSymmetric(
            data instanceof Uint8Array ? data : data.toDer(),
            key,
            this.toSymmetricEncryptionAlgorithmParams(),
        )
    }

    static fromAsn1(
        asn1: asn1js.BaseBlock,
    ): ContentEncryptionAlgorithmIdentifier {
        const algId = AlgorithmIdentifier.fromAsn1(asn1)
        return new ContentEncryptionAlgorithmIdentifier({
            algorithm: algId.algorithm.value,
            parameters: algId.parameters,
        })
    }

    setNoPadding(noPadding: boolean) {
        this.noPadding = noPadding
    }

    getNoPadding(): boolean {
        return this.noPadding
    }

    static fromDer(bytes: Uint8Array): ContentEncryptionAlgorithmIdentifier {
        return new ContentEncryptionAlgorithmIdentifier(
            AlgorithmIdentifier.fromDer(bytes),
        )
    }
}

/**
 * Represents the pSource algorithm for RSA-OAEP
 *
 * @asn
 * ```asn
 * PSourceAlgorithm ::= AlgorithmIdentifier
 * ```
 */
export class PSourceAlgorithm extends AlgorithmIdentifier {
    constructor(
        options: {
            parameters?: Asn1Any
        } = {},
    ) {
        super({
            algorithm: OIDs.RSA.PSPECIFIED,
            parameters: options.parameters,
        })
    }

    static fromAsn1(value: Asn1BaseBlock): PSourceAlgorithm {
        const algorithm = AlgorithmIdentifier.fromAsn1(value)

        if (algorithm.algorithm.toString() !== OIDs.RSA.PSPECIFIED) {
            throw new Asn1ParseError('Invalid PSourceAlgorithm value')
        }

        return new PSourceAlgorithm({ parameters: algorithm.parameters })
    }

    getLabel(): string {
        return new TextDecoder().decode(this.getLabelBytes())
    }

    getLabelBytes(): Uint8Array {
        if (!this.parameters) {
            return new Uint8Array(0)
        }

        const params = this.parameters.parseAs(OctetString)

        return params.bytes
    }
}
