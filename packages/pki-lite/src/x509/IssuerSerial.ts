import { Integer } from '../asn1/Integer.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'
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

    toAsn1(): Asn1Node {
        return der.sequence([this.issuer.toAsn1(), this.serialNumber.toAsn1()])
    }

    static fromAsn1(asn1: Asn1Node): IssuerSerial {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements in SEQUENCE',
            )
        }

        const issuer = GeneralNames.fromAsn1(sequence.children[0])
        const serialNumber = Integer.fromAsn1(sequence.children[1])

        return new IssuerSerial({ issuer, serialNumber })
    }
}
