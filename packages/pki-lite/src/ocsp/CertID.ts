import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Integer } from '../asn1/Integer.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * CertID ::= SEQUENCE {
 *     hashAlgorithm           AlgorithmIdentifier,
 *     issuerNameHash          OCTET STRING, -- Hash of issuer's DN
 *     issuerKeyHash           OCTET STRING, -- Hash of issuer's key
 *     serialNumber            CertificateSerialNumber
 * }
 */
export class CertID extends PkiBase<CertID> {
    hashAlgorithm: AlgorithmIdentifier
    issuerNameHash: OctetString
    issuerKeyHash: OctetString
    serialNumber: Integer

    constructor(options: {
        hashAlgorithm: AlgorithmIdentifier
        issuerNameHash: OctetString | Uint8Array | string
        issuerKeyHash: OctetString | Uint8Array | string
        serialNumber: Uint8Array | number | bigint | string | Integer
    }) {
        super()
        const { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber } =
            options
        this.hashAlgorithm = hashAlgorithm
        this.issuerNameHash =
            issuerNameHash instanceof OctetString
                ? issuerNameHash
                : new OctetString({ bytes: issuerNameHash })
        this.issuerKeyHash =
            issuerKeyHash instanceof OctetString
                ? issuerKeyHash
                : new OctetString({ bytes: issuerKeyHash })
        this.serialNumber = new Integer({ value: serialNumber })
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.hashAlgorithm.toAsn1(),
                this.issuerNameHash.toAsn1(),
                this.issuerKeyHash.toAsn1(),
                this.serialNumber.toAsn1(),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): CertID {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (sequence.valueBlock.value.length !== 4) {
            throw new Asn1ParseError('Invalid CertID: expected 4 elements')
        }

        const hashAlgorithm = AlgorithmIdentifier.fromAsn1(
            sequence.valueBlock.value[0],
        )
        const issuerNameHash = OctetString.fromAsn1(
            sequence.valueBlock.value[1],
        )
        const issuerKeyHash = OctetString.fromAsn1(sequence.valueBlock.value[2])

        const serialNumberBlock = sequence.valueBlock.value[3] as asn1js.Integer
        const serialNumber = serialNumberBlock.valueBlock.valueHexView

        return new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })
    }

    static fromDer(der: Uint8Array): CertID {
        return CertID.fromAsn1(derToAsn1(der))
    }
}
