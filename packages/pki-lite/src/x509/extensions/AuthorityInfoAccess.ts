import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import {
    Asn1BaseBlock,
    asn1js,
    ObjectIdentifierString,
    PkiBase,
    PkiSequence,
} from '../../core/PkiBase.js'
import { GeneralName } from '../GeneralName.js'

/**
 * Represents AccessDescription structure described in RFC5280
 *
 * @asn
 * ```asn
 * AccessDescription  ::=  SEQUENCE {
 *    accessMethod          OBJECT IDENTIFIER,
 *    accessLocation        GeneralName
 * }
 * ```
 */
export class AccessDescription extends PkiBase<AccessDescription> {
    accessMethod: ObjectIdentifier
    accessLocation: GeneralName

    constructor(options: {
        accessMethod: ObjectIdentifier | ObjectIdentifierString
        accessLocation: GeneralName
    }) {
        super()
        this.accessMethod = new ObjectIdentifier({
            value: options.accessMethod,
        })
        this.accessLocation = options.accessLocation
    }

    toAsn1() {
        return new asn1js.Sequence({
            value: [this.accessMethod.toAsn1(), this.accessLocation.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('ASN.1 structure should be a sequence')
        }

        if (asn1.valueBlock.value.length !== 2) {
            throw new Asn1ParseError('ASN.1 sequence should have 2 elements')
        }

        return new AccessDescription({
            accessMethod: ObjectIdentifier.fromAsn1(asn1.valueBlock.value[0])
                .value,
            accessLocation: GeneralName.fromAsn1(asn1.valueBlock.value[1]),
        })
    }
}
/**
 * Represents AuthorityInfoAccess extension described in RFC5280
 *
 * @asn
 * ```asn
 * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 *
 * AuthorityInfoAccessSyntax  ::=
 *          SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 *   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
 *
 *   id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
 *
 *   id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 * ```
 */
export class AuthorityInfoAccess extends PkiSequence<AccessDescription> {
    static fromAsn1(asn1: Asn1BaseBlock) {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('ASN.1 structure should be a sequence')
        }

        return new AuthorityInfoAccess(
            ...asn1.valueBlock.value.map(AccessDescription.fromAsn1),
        )
    }
}
