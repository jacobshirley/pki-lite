import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1Any,
    Asn1BaseBlock,
    asn1js,
    Choice,
    PkiBase,
    PkiSequence,
} from '../core/PkiBase.js'
import { Name } from './Name.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { OctetString } from '../asn1/OctetString.js'
import { IA5String } from '../asn1/IA5String.js'
import { DirectoryString } from './DirectoryString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

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

    toAsn1() {
        return new asn1js.Sequence({
            value: [this.typeID.toAsn1(), this.value.toAsn1()],
        })
    }

    static fromAsn1(asn1: asn1js.Sequence) {
        const sequence = asn1.valueBlock.value

        if (sequence.length !== 2) {
            throw new Asn1ParseError('Invalid AnotherName ASN.1 structure')
        }

        const typeID = sequence[0]
        if (!(typeID instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid AnotherName ASN.1 structure: typeID is not an ObjectIdentifier',
            )
        }

        const value = sequence[1]

        return new AnotherName({ typeID: typeID.valueBlock.toString(), value })
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
        return new asn1js.Sequence({
            value: [
                ...(this.nameAssigner
                    ? [
                          new asn1js.Constructed({
                              idBlock: { tagClass: 3, tagNumber: 0 },
                              value: [this.nameAssigner.toAsn1()],
                          }),
                      ]
                    : []),
                this.partyName.toAsn1(),
            ],
        })
    }

    static fromAsn1(asn1: asn1js.Sequence) {
        const sequence = asn1.valueBlock.value

        if (sequence.length < 1 || sequence.length > 2) {
            throw new Asn1ParseError('Invalid EDIPartyName ASN.1 structure')
        }

        let nameAssigner: DirectoryString | undefined
        let partyName: DirectoryString

        if (sequence.length === 2) {
            const nameAssignerBlock = sequence[0]
            if (
                !(nameAssignerBlock instanceof asn1js.Constructed) ||
                nameAssignerBlock.idBlock.tagClass !== 3 ||
                nameAssignerBlock.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid EDIPartyName ASN.1 structure: nameAssigner is not correctly tagged',
                )
            }
            nameAssigner = DirectoryString.fromAsn1(
                nameAssignerBlock.valueBlock.value[0],
            )
            partyName = DirectoryString.fromAsn1(sequence[1])
        } else {
            partyName = DirectoryString.fromAsn1(sequence[0])
        }

        return new EDIPartyName({ nameAssigner, partyName })
    }
}

export class otherName extends AnotherName {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 0 },
            value: [super.toAsn1()],
        })
    }
}

export class rfc822Name extends IA5String {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        return new rfc822Name({ value: super.fromAsn1(asn1).bytes })
    }
}

export class dNSName extends IA5String {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 2 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        return new dNSName({ value: super.fromAsn1(asn1).bytes })
    }
}

/** TODO: define this properly */
export class x400Address extends Any {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 3 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        return new x400Address({ derBytes: asn1 })
    }
}

export class directoryName extends Name.RDNSequence {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 4 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        if (!(asn1 instanceof asn1js.Sequence)) {
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
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 5 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for ediPartyName',
            )
        }

        return new ediPartyName(EDIPartyName.fromAsn1(asn1))
    }
}

export class uniformResourceIdentifier extends IA5String {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 6 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        if (asn1 instanceof asn1js.Primitive) {
            return new uniformResourceIdentifier({
                value: asn1.valueBlock.valueHexView,
            })
        }

        return new uniformResourceIdentifier({
            value: super.fromAsn1(asn1).bytes,
        })
    }
}

export class iPAddress extends OctetString {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 7 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        return new iPAddress({ bytes: super.fromAsn1(asn1).bytes })
    }
}

export class registeredID extends ObjectIdentifier {
    toAsn1(): asn1js.Sequence {
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 8 },
            value: [super.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock) {
        return new registeredID({ value: super.fromAsn1(asn1).value })
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
    fromAsn1(asn1: Asn1BaseBlock): GeneralName {
        if (
            !(asn1 instanceof asn1js.Constructed) &&
            !(asn1 instanceof asn1js.Primitive)
        ) {
            throw new Asn1ParseError(
                'Invalid GeneralName ASN.1 structure: not a constructed or primitive type',
            )
        }

        const value =
            asn1 instanceof asn1js.Constructed
                ? (asn1.valueBlock.value[0] as Asn1BaseBlock)
                : asn1

        switch (asn1.idBlock.tagNumber) {
            case 0:
                return otherName.fromAsn1(value as asn1js.Sequence)
            case 1:
                return rfc822Name.fromAsn1(value as asn1js.IA5String)
            case 2:
                return dNSName.fromAsn1(value as asn1js.IA5String)
            case 3:
                return x400Address.fromAsn1(value as Asn1BaseBlock)
            case 4:
                return directoryName.fromAsn1(value as asn1js.Sequence)
            case 5:
                return ediPartyName.fromAsn1(value as asn1js.Sequence)
            case 6:
                return uniformResourceIdentifier.fromAsn1(
                    value as asn1js.IA5String,
                )
            case 7:
                return iPAddress.fromAsn1(value as asn1js.OctetString)
            case 8:
                return registeredID.fromAsn1(value as asn1js.ObjectIdentifier)
            default:
                throw new Asn1ParseError(
                    'Invalid GeneralName ASN.1 structure: unknown tag number ' +
                        asn1.idBlock.tagNumber,
                )
        }
    },
    toAsn1(value: GeneralName) {
        return value.toAsn1()
    },
})

export class GeneralNames extends PkiSequence<GeneralName> {
    static fromAsn1(asn1: Asn1BaseBlock): GeneralNames {
        if (asn1 instanceof asn1js.Primitive) {
            return new GeneralNames(GeneralName.fromAsn1(asn1))
        }

        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid GeneralNames ASN.1 structure. Expected Sequence but got ' +
                    asn1.constructor.name,
            )
        }
        return new GeneralNames(
            ...asn1.valueBlock.value.map((v) => GeneralName.fromAsn1(v)),
        )
    }
}
