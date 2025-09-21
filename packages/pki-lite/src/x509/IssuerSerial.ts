import { Integer } from '../asn1/Integer.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { GeneralName, GeneralNames } from './GeneralName.js'
import { Name } from './Name.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the ASN.1 IssuerSerial structure.
 *
 * @asn
 * ```asn
 * IssuerSerial ::= SEQUENCE {
 *      issuer GeneralNames,
 *      serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER
 * ```
 */
export class IssuerSerial extends PkiBase<IssuerSerial> {
    issuer: GeneralNames
    serialNumber: Integer

    constructor(options: {
        issuer: GeneralNames | Name
        serialNumber: Integer
    }) {
        super()
        this.issuer =
            options.issuer instanceof Name.RDNSequence
                ? new GeneralNames(
                      GeneralName.directoryName.fromName(options.issuer),
                  )
                : options.issuer
        this.serialNumber = options.serialNumber
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.issuer.toAsn1(), this.serialNumber.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): IssuerSerial {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (sequence.valueBlock.value.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements in SEQUENCE',
            )
        }

        const issuer = GeneralNames.fromAsn1(sequence.valueBlock.value[0])
        const serialNumber = Integer.fromAsn1(sequence.valueBlock.value[1])

        return new IssuerSerial({ issuer, serialNumber })
    }
}
