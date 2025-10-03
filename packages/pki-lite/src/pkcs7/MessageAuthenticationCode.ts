import { Asn1BaseBlock, asn1js } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

import { OctetString } from '../asn1/OctetString.js'

/**
 * Message Authentication Code
 *
 * @asn
 * ```asn
 * MessageAuthenticationCode ::= OCTET STRING
 * ```
 */
export class MessageAuthenticationCode extends OctetString {
    static fromAsn1(asn1: Asn1BaseBlock): MessageAuthenticationCode {
        if (!(asn1 instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for MessageAuthenticationCode',
            )
        }

        return new MessageAuthenticationCode({
            bytes: asn1.valueBlock.valueHexView,
        })
    }
}
