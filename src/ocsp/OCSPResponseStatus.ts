import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * OCSPResponseStatus ::= ENUMERATED {
 *     successful            (0),  -- Response has valid confirmations
 *     malformedRequest      (1),  -- Illegal confirmation request
 *     internalError         (2),  -- Internal error in issuer
 *     tryLater              (3),  -- Try again later
 *                                 -- (4) is not used
 *     sigRequired           (5),  -- Must sign the request
 *     unauthorized          (6)   -- Request unauthorized
 * }
 */
export class OCSPResponseStatus extends PkiBase<OCSPResponseStatus> {
    static successful = new OCSPResponseStatus(0)
    static malformedRequest = new OCSPResponseStatus(1)
    static internalError = new OCSPResponseStatus(2)
    static tryLater = new OCSPResponseStatus(3)
    static sigRequired = new OCSPResponseStatus(5)
    static unauthorized = new OCSPResponseStatus(6)

    value: number

    constructor(value: number | OCSPResponseStatus) {
        super()
        this.value = value instanceof OCSPResponseStatus ? value.value : value
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Enumerated({ value: this.value })
    }

    static fromAsn1(asn1: Asn1BaseBlock): OCSPResponseStatus {
        if (!(asn1 instanceof asn1js.Enumerated)) {
            throw new Asn1ParseError(
                'Invalid OCSPResponseStatus ASN.1 structure. Expected ENUMERATED but got ' +
                    asn1.constructor.name,
            )
        }
        return new OCSPResponseStatus(asn1.valueBlock.valueDec)
    }
}
