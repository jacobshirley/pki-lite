import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the reason for certificate revocation.
 *
 * @asn
 * ```asn
 * CRLReason ::= ENUMERATED {
 *       unspecified             (0),
 *       keyCompromise           (1),
 *       cACompromise            (2),
 *       affiliationChanged      (3),
 *       superseded              (4),
 *       cessationOfOperation    (5),
 *       certificateHold         (6),
 *            -- value 7 is not used
 *       removeFromCRL           (8),
 *       privilegeWithdrawn      (9),
 *       aACompromise           (10)
 * }
 */
export class CRLReason extends PkiBase<CRLReason> {
    static unspecified = new CRLReason(0)
    static keyCompromise = new CRLReason(1)
    static cACompromise = new CRLReason(2)
    static affiliationChanged = new CRLReason(3)
    static superseded = new CRLReason(4)
    static cessationOfOperation = new CRLReason(5)
    static certificateHold = new CRLReason(6)
    static removeFromCRL = new CRLReason(8)
    static privilegeWithdrawn = new CRLReason(9)
    static aACompromise = new CRLReason(10)

    value: number

    constructor(value: number) {
        super()
        this.value = value
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Enumerated({ value: this.value })
    }

    static fromAsn1(asn1: Asn1BaseBlock): CRLReason {
        if (!(asn1 instanceof asn1js.Enumerated)) {
            throw new Asn1ParseError(
                'Invalid CRLReason ASN.1 structure. Expected ENUMERATED but got ' +
                    asn1.constructor.name,
            )
        }
        return new CRLReason(asn1.valueBlock.valueDec)
    }
}
