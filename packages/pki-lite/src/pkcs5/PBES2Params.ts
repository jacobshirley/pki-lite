import { Asn1BaseBlock, asn1js, derToAsn1, PkiBase } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'

/**
 * Represents PBES2-params structure.
 *
 * @asn
 * ```asn
 * PBES2-params ::= SEQUENCE {
 *   keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
 *   encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
 * }
 * ```
 */
export class PBES2Params extends PkiBase<PBES2Params> {
    keyDerivationFunc: AlgorithmIdentifier
    encryptionScheme: AlgorithmIdentifier

    constructor(options: {
        keyDerivationFunc: AlgorithmIdentifier
        encryptionScheme: AlgorithmIdentifier
    }) {
        super()
        this.keyDerivationFunc = options.keyDerivationFunc
        this.encryptionScheme = options.encryptionScheme
    }

    toAsn1() {
        return new asn1js.Sequence({
            value: [
                this.keyDerivationFunc.toAsn1(),
                this.encryptionScheme.toAsn1(),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PBES2Params {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Error('PBES2Params: expected SEQUENCE')
        }
        if (asn1.valueBlock.value.length !== 2) {
            throw new Error('PBES2Params: expected 2 elements in SEQUENCE')
        }
        const keyDerivationFunc = AlgorithmIdentifier.fromAsn1(
            asn1.valueBlock.value[0],
        )
        const encryptionScheme = AlgorithmIdentifier.fromAsn1(
            asn1.valueBlock.value[1],
        )
        return new PBES2Params({
            keyDerivationFunc,
            encryptionScheme,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): PBES2Params {
        return PBES2Params.fromAsn1(derToAsn1(der))
    }
}
