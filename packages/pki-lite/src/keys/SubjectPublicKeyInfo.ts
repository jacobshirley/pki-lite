import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    pemToDer,
    PkiBase,
} from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { RSAPublicKey } from './RSAPublicKey.js'
import { OIDs } from '../core/OIDs.js'
import { ECPublicKey } from './ECPublicKey.js'
import { BitString } from '../asn1/BitString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the subject key information.
 *
 * @asn
 * ```asn
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING
 * }
 * ```
 */
export class SubjectPublicKeyInfo extends PkiBase<SubjectPublicKeyInfo> {
    algorithm: AlgorithmIdentifier
    subjectPublicKey: BitString

    constructor(options: {
        algorithm: AlgorithmIdentifier
        subjectPublicKey:
            | Uint8Array<ArrayBuffer>
            | RSAPublicKey
            | ECPublicKey
            | BitString
    }) {
        super()
        this.algorithm = options.algorithm
        this.subjectPublicKey = new BitString({
            value: options.subjectPublicKey,
        })
    }

    /**
     * Converts the subject key information to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.algorithm.toAsn1(), this.subjectPublicKey.toAsn1()],
        })
    }

    /**
     * Creates a SubjectPublicKeyInfo from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns A SubjectPublicKeyInfo
     */
    static fromAsn1(asn1: asn1js.BaseBlock): SubjectPublicKeyInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('Expected Sequence')
        }

        if (asn1.valueBlock.value.length !== 2) {
            throw new Asn1ParseError(
                'Expected 2 elements in SubjectPublicKeyInfo sequence',
            )
        }

        const algorithmBlock = asn1.valueBlock.value[0]
        const subjectPublicKeyBlock = asn1.valueBlock.value[1]

        const algorithm = AlgorithmIdentifier.fromAsn1(algorithmBlock)

        if (!(subjectPublicKeyBlock instanceof asn1js.BitString)) {
            throw new Asn1ParseError('Expected BitString for subjectPublicKey')
        }

        const subjectPublicKey = new Uint8Array(
            subjectPublicKeyBlock.valueBlock.valueHexView,
        )

        return new SubjectPublicKeyInfo({ algorithm, subjectPublicKey })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): SubjectPublicKeyInfo {
        return this.fromAsn1(derToAsn1(der))
    }

    static fromPem(pem: string): SubjectPublicKeyInfo {
        return this.fromDer(pemToDer(pem, 'PUBLIC KEY'))
    }

    getRsaPublicKey(): RSAPublicKey {
        if (this.algorithm.algorithm.toString() !== OIDs.RSA.ENCRYPTION) {
            throw new Error('SubjectPublicKeyInfo is not RSA')
        }
        return RSAPublicKey.fromDer(this.subjectPublicKey.bytes)
    }

    getEcPublicKey(): ECPublicKey {
        if (this.algorithm.algorithm.toString() !== OIDs.EC.PUBLIC_KEY) {
            throw new Error('SubjectPublicKeyInfo is not EC')
        }
        return ECPublicKey.fromRaw(this.subjectPublicKey.bytes)
    }

    getPublicKey(): ECPublicKey | RSAPublicKey {
        if (this.algorithm.algorithm.toString() === OIDs.EC.PUBLIC_KEY) {
            return this.getEcPublicKey()
        } else if (
            this.algorithm.algorithm.toString() === OIDs.RSA.ENCRYPTION
        ) {
            return this.getRsaPublicKey()
        }
        throw new Error('Unsupported key algorithm')
    }
}
