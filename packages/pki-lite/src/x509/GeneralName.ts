import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1Any,
    Asn1Node,
    Choice,
    der,
    PkiBase,
    PkiSequence,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { Name } from './Name.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { OctetString } from '../asn1/OctetString.js'
import { IA5String } from '../asn1/IA5String.js'
import { DirectoryString } from './DirectoryString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { implicitTag, isContextTag } from '../core/tagging.js'

/** The content octets of a GeneralName string alternative ([1], [2], [6]). */
function implicitStringBytes(asn1: Asn1Node): Uint8Array<ArrayBuffer> {
    if (asn1.constructed && asn1.tagClass === TagClass.Context) {
        // Explicitly tagged form written by earlier versions of this library
        return IA5String.fromAsn1(asn1.children[0]).bytes
    }
    if (asn1.tagClass === TagClass.Context) {
        return asn1.bytes()
    }
    return IA5String.fromAsn1(asn1).bytes
}

export class AnotherName extends PkiBase<AnotherName> {
    typeID: ObjectIdentifier
    value: Any

    constructor(options: {
        typeID: string | ObjectIdentifier
        value: Asn1Any
    }) {
        super()

        const { typeID, value } = options

        this.typeID = new ObjectIdentifier({ value: typeID })
        this.value = new Any({ derBytes: value })
    }

    /**
     * The children of the structure: `type-id OBJECT IDENTIFIER` followed by
     * `value [0] EXPLICIT ANY`.
     */
    protected toAsn1Children(): Asn1Node[] {
        return [this.typeID.toAsn1(), der.constructed(0, [this.value.toAsn1()])]
    }

    toAsn1() {
        return der.sequence(this.toAsn1Children())
    }

    /**
     * @param asn1 A SEQUENCE (or an element whose children are the same two
     * fields, as is the case for the implicitly tagged otherName)
     */
    static fromAsn1(asn1: Asn1Node) {
        const sequence = asn1.children

        if (sequence.length !== 2) {
            throw new Asn1ParseError('Invalid AnotherName ASN.1 structure')
        }

        const typeID = sequence[0]
        if (!typeID.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid AnotherName ASN.1 structure: typeID is not an ObjectIdentifier',
            )
        }

        let value = sequence[1]
        if (
            value?.constructed &&
            isContextTag(value, 0) &&
            value.children.length === 1
        ) {
            value = value.children[0]
        }

        return new AnotherName({ typeID: der.readOid(typeID), value })
    }
}

export class EDIPartyName extends PkiBase<EDIPartyName> {
    nameAssigner?: DirectoryString
    partyName: DirectoryString

    constructor(options: {
        nameAssigner?: string | DirectoryString
        partyName: string | DirectoryString
    }) {
        super()

        const { nameAssigner, partyName } = options

        this.nameAssigner =
            typeof nameAssigner === 'string'
                ? new UTF8String({ value: nameAssigner })
                : nameAssigner
        this.partyName =
            typeof partyName === 'string'
                ? new UTF8String({ value: partyName })
                : partyName
    }

    toAsn1() {
        return der.sequence([
            ...(this.nameAssigner
                ? [der.constructed(0, [this.nameAssigner.toAsn1()])]
                : []),
            der.constructed(1, [this.partyName.toAsn1()]),
        ])
    }

    /**
     * @param asn1 A SEQUENCE (or an element whose children are the same fields,
     * as is the case for the implicitly tagged ediPartyName)
     */
    static fromAsn1(asn1: Asn1Node) {
        const sequence = asn1.children

        if (sequence.length < 1 || sequence.length > 2) {
            throw new Asn1ParseError('Invalid EDIPartyName ASN.1 structure')
        }

        const unwrap = (block: Asn1Node, tagNumber: number) => {
            if (!block?.constructed || !isContextTag(block, tagNumber)) {
                return undefined
            }
            return DirectoryString.fromAsn1(block.children[0])
        }

        let nameAssigner: DirectoryString | undefined
        let partyName: DirectoryString | undefined

        if (sequence.length === 2) {
            nameAssigner = unwrap(sequence[0], 0)
            if (!nameAssigner) {
                throw new Asn1ParseError(
                    'Invalid EDIPartyName ASN.1 structure: nameAssigner is not correctly tagged',
                )
            }
            partyName =
                unwrap(sequence[1], 1) ?? DirectoryString.fromAsn1(sequence[1])
        } else {
            // partyName only; an untagged value is the form written by earlier versions
            partyName =
                unwrap(sequence[0], 1) ?? DirectoryString.fromAsn1(sequence[0])
        }

        return new EDIPartyName({ nameAssigner, partyName })
    }
}

export class otherName extends AnotherName {
    /** [0] IMPLICIT AnotherName: the SEQUENCE's children sit directly in [0] */
    toAsn1(): Asn1Node {
        return der.constructed(0, this.toAsn1Children())
    }

    static fromAsn1(asn1: Asn1Node) {
        if (!asn1.constructed) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected a constructed value for otherName',
            )
        }
        // Earlier versions wrapped the whole SEQUENCE in an explicit [0]
        const [first] = asn1.children
        const sequence =
            asn1.children.length === 1 && first.is(UniversalTag.Sequence)
                ? first
                : asn1
        const { typeID, value } = AnotherName.fromAsn1(sequence)
        return new otherName({ typeID, value: value.toAsn1() })
    }
}

export class rfc822Name extends IA5String {
    toAsn1() {
        return implicitTag(super.toAsn1(), 1)
    }

    static fromAsn1(asn1: Asn1Node) {
        return new rfc822Name({ value: implicitStringBytes(asn1) })
    }
}

export class dNSName extends IA5String {
    toAsn1() {
        return implicitTag(super.toAsn1(), 2)
    }

    static fromAsn1(asn1: Asn1Node) {
        return new dNSName({ value: implicitStringBytes(asn1) })
    }
}

/**
 * x400Address [3] ORAddress. The ORAddress structure is not modelled: the
 * original element is kept as-is and written back unchanged.
 */
export class x400Address extends Any {
    toAsn1() {
        const block = super.toAsn1()
        return block.tagClass === TagClass.Context
            ? block
            : implicitTag(block, 3)
    }

    static fromAsn1(asn1: Asn1Node) {
        return new x400Address({ derBytes: asn1 })
    }
}

/** directoryName [4] Name; Name is a CHOICE, so the tag is EXPLICIT. */
export class directoryName extends Name.RDNSequence {
    toAsn1(): Asn1Node {
        return der.constructed(4, [super.toAsn1()])
    }

    static fromAsn1(asn1: Asn1Node) {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for directoryName',
            )
        }

        return new directoryName(
            ...Name.RDNSequence.fromAsn1(asn1).map((rdn) => rdn),
        )
    }

    static fromName(rdnSequence: Name): directoryName {
        return new directoryName(...rdnSequence.map((rdn) => rdn))
    }
}

export class ediPartyName extends EDIPartyName {
    /** [5] IMPLICIT EDIPartyName */
    toAsn1() {
        return implicitTag(super.toAsn1(), 5)
    }

    static fromAsn1(asn1: Asn1Node) {
        if (!asn1.constructed) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for ediPartyName',
            )
        }
        // Earlier versions wrapped the whole SEQUENCE in an explicit [5]
        const [first] = asn1.children
        const sequence =
            asn1.children.length === 1 && first.is(UniversalTag.Sequence)
                ? first
                : asn1
        return new ediPartyName(EDIPartyName.fromAsn1(sequence))
    }
}

export class uniformResourceIdentifier extends IA5String {
    toAsn1() {
        return implicitTag(super.toAsn1(), 6)
    }

    static fromAsn1(asn1: Asn1Node) {
        return new uniformResourceIdentifier({
            value: implicitStringBytes(asn1),
        })
    }
}

export class iPAddress extends OctetString {
    toAsn1() {
        return implicitTag(super.toAsn1(), 7)
    }

    static fromAsn1(asn1: Asn1Node) {
        if (asn1.constructed && asn1.tagClass === TagClass.Context) {
            // explicit form written by earlier versions
            return new iPAddress({
                bytes: OctetString.fromAsn1(asn1.children[0]).bytes,
            })
        }
        if (asn1.tagClass === TagClass.Context) {
            return new iPAddress({
                bytes: asn1.bytes(),
            })
        }
        return new iPAddress({ bytes: OctetString.fromAsn1(asn1).bytes })
    }
}

export class registeredID extends ObjectIdentifier {
    toAsn1() {
        return implicitTag(super.toAsn1(), 8)
    }

    static fromAsn1(asn1: Asn1Node) {
        if (asn1.constructed && asn1.tagClass === TagClass.Context) {
            // explicit form written by earlier versions
            return new registeredID({
                value: ObjectIdentifier.fromAsn1(asn1.children[0]).value,
            })
        }
        if (asn1.tagClass === TagClass.Context) {
            // [8] IMPLICIT OBJECT IDENTIFIER
            return new registeredID({
                value: der.readOid(asn1.retag(UniversalTag.ObjectIdentifier)),
            })
        }
        return new registeredID({
            value: ObjectIdentifier.fromAsn1(asn1).value,
        })
    }
}

export type GeneralName =
    | otherName
    | rfc822Name
    | dNSName
    | x400Address
    | directoryName
    | ediPartyName
    | uniformResourceIdentifier
    | iPAddress
    | registeredID

export const GeneralName = Choice('GeneralName', {
    otherName,
    rfc822Name,
    dNSName,
    x400Address,
    directoryName,
    ediPartyName,
    uniformResourceIdentifier,
    iPAddress,
    registeredID,
    fromAsn1(asn1: Asn1Node): GeneralName {
        if (asn1.tagClass !== TagClass.Context) {
            throw new Asn1ParseError(
                'Invalid GeneralName ASN.1 structure: not a constructed or primitive type',
            )
        }

        switch (asn1.tag) {
            case 0:
                return otherName.fromAsn1(asn1)
            case 1:
                return rfc822Name.fromAsn1(asn1)
            case 2:
                return dNSName.fromAsn1(asn1)
            case 3:
                return x400Address.fromAsn1(asn1)
            case 4:
                return directoryName.fromAsn1(asn1.children[0])
            case 5:
                return ediPartyName.fromAsn1(asn1)
            case 6:
                return uniformResourceIdentifier.fromAsn1(asn1)
            case 7:
                return iPAddress.fromAsn1(asn1)
            case 8:
                return registeredID.fromAsn1(asn1)
            default:
                throw new Asn1ParseError(
                    'Invalid GeneralName ASN.1 structure: unknown tag number ' +
                        asn1.tag,
                )
        }
    },
    toAsn1(value: GeneralName) {
        return value.toAsn1()
    },
})

export class GeneralNames extends PkiSequence<GeneralName> {
    /**
     * Encodes these names as an implicitly tagged `[tagNumber] GeneralNames`: a
     * constructed `[tagNumber]` holding the GeneralName elements directly (no SEQUENCE).
     */
    toImplicitAsn1(tagNumber: number): Asn1Node {
        return der.constructed(tagNumber, this.toAsn1().children)
    }

    /**
     * Reads an implicitly tagged `[n] GeneralNames` as written by `toImplicitAsn1`.
     * The explicit form written by earlier versions (the SEQUENCE wrapped in [n]) is
     * accepted too.
     */
    static fromImplicitAsn1(asn1: Asn1Node): GeneralNames {
        if (!asn1.constructed) {
            throw new Asn1ParseError(
                'Invalid GeneralNames ASN.1 structure. Expected Constructed but got ' +
                    asn1.describe(),
            )
        }
        const [first] = asn1.children
        if (asn1.children.length === 1 && first.is(UniversalTag.Sequence)) {
            return GeneralNames.fromAsn1(first)
        }
        return new GeneralNames(
            ...asn1.children.map((v) => GeneralName.fromAsn1(v)),
        )
    }

    static fromAsn1(asn1: Asn1Node): GeneralNames {
        // A single implicitly tagged (primitive) GeneralName
        if (!asn1.constructed && asn1.tagClass !== TagClass.Universal) {
            return new GeneralNames(GeneralName.fromAsn1(asn1))
        }

        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid GeneralNames ASN.1 structure. Expected Sequence but got ' +
                    asn1.describe(),
            )
        }
        return new GeneralNames(
            ...asn1.children.map((v) => GeneralName.fromAsn1(v)),
        )
    }
}
