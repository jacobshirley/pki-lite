import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    PkiSequence,
} from '../core/PkiBase.js'
import { SafeBag } from './SafeBag.js'

/**
 * Represents the SafeContents structure in a PKCS#12 file.
 *
 * @asn
 * ```asn
 * SafeContents ::= SEQUENCE OF SafeBag
 * ```
 */
export class SafeContents extends PkiSequence<SafeBag> {
    static fromAsn1(asn1: Asn1BaseBlock): SafeContents {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'SafeContents: expected SEQUENCE but got ' +
                    asn1.constructor.name,
            )
        }
        const bags = asn1.valueBlock.value.map((x) => SafeBag.fromAsn1(x))
        return new SafeContents(...bags)
    }

    static fromDer(der: Uint8Array): SafeContents {
        return SafeContents.fromAsn1(derToAsn1(der))
    }
}
