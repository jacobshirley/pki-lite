import { Any } from '../../asn1/Any.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import {
    Asn1Any,
    Asn1BaseBlock,
    asn1js,
    ObjectIdentifierString,
    PkiBase,
} from '../../core/PkiBase.js'
import { BasicOCSPResponse } from '../../ocsp/BasicOCSPResponse.js'
import { CertificateList } from '../CertificateList.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the OtherRevVals structure used in .
 *
 * @asn
 * ```asn
 * OtherRevVals ::= SEQUENCE {
 *     OtherRevValType   OtherRevValType,
 *     OtherRevVals      ANY DEFINED BY OtherRevValType
 * }
 * ```
 */
export class OtherRevVals extends PkiBase<OtherRevVals> {
    OtherRevValType: ObjectIdentifier
    OtherRevVals: Any

    constructor(options: {
        OtherRevValType: ObjectIdentifierString
        OtherRevVals: Asn1Any
    }) {
        super()
        this.OtherRevValType = new ObjectIdentifier({
            value: options.OtherRevValType,
        })
        this.OtherRevVals = new Any({ derBytes: options.OtherRevVals })
    }

    toAsn1() {
        return new asn1js.Sequence({
            value: [this.OtherRevValType.toAsn1(), this.OtherRevVals.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): OtherRevVals {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }
        const type = asn1.valueBlock.value[0] as asn1js.ObjectIdentifier
        const value = asn1.valueBlock.value[1]

        return new OtherRevVals({
            OtherRevValType: type.valueBlock.toString(),
            OtherRevVals: new Any({ derBytes: value }),
        })
    }
}

/**
 * Represents the RevocationValues attribute defined by https://datatracker.ietf.org/doc/html/rfc5126#page-54.
 *
 * @asn
 * ```asn
 * RevocationValues ::=  SEQUENCE {
 *    crlVals          [0] SEQUENCE OF CertificateList OPTIONAL,
 *    ocspVals         [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
 *    otherRevVals     [2] OtherRevVals OPTIONAL
 * }
 * ```
 */
export class RevocationValues extends PkiBase<RevocationValues> {
    crlVals?: CertificateList[]
    ocspVals?: BasicOCSPResponse[]
    otherRevVals?: OtherRevVals[]

    constructor(options: {
        crlVals?: CertificateList[]
        ocspVals?: BasicOCSPResponse[]
        otherRevVals?: OtherRevVals[]
    }) {
        super()
        this.crlVals = options.crlVals
        this.ocspVals = options.ocspVals
        this.otherRevVals = options.otherRevVals
    }

    toAsn1(): asn1js.Sequence {
        const values: asn1js.Constructed[] = []

        if (this.crlVals && this.crlVals.length > 0) {
            const crlSeq = new asn1js.Sequence({
                value: this.crlVals.map((crl) => crl.toAsn1()),
            })
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [crlSeq],
                }),
            )
        }

        if (this.ocspVals && this.ocspVals.length > 0) {
            const ocspSeq = new asn1js.Sequence({
                value: this.ocspVals.map((ocsp) => ocsp.toAsn1()),
            })
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 },
                    value: [ocspSeq],
                }),
            )
        }

        if (this.otherRevVals && this.otherRevVals.length > 0) {
            const otherRevValsSeq = new asn1js.Sequence({
                value: this.otherRevVals.map((ori) => ori.toAsn1()),
            })
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 },
                    value: [otherRevValsSeq],
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): RevocationValues {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const crls: CertificateList[] = []
        const ocsps: BasicOCSPResponse[] = []
        const otherRevVals: OtherRevVals[] = []

        for (const element of asn1.valueBlock.value) {
            if (!(element instanceof asn1js.Constructed)) {
                continue
            }

            const tagNumber = element.idBlock.tagNumber

            if (tagNumber === 0) {
                const crlSeq = element.valueBlock.value[0] as asn1js.Sequence
                for (const crlAsn1 of crlSeq.valueBlock.value) {
                    crls.push(
                        CertificateList.fromAsn1(crlAsn1 as asn1js.Sequence),
                    )
                }
            } else if (tagNumber === 1) {
                const ocspSeq = element.valueBlock.value[0] as asn1js.Sequence
                for (const ocspAsn1 of ocspSeq.valueBlock.value) {
                    ocsps.push(
                        BasicOCSPResponse.fromAsn1(ocspAsn1 as asn1js.Sequence),
                    )
                }
            } else if (tagNumber === 2) {
                const oriSeq = element.valueBlock.value[0] as asn1js.Sequence
                for (const oriAsn1 of oriSeq.valueBlock.value) {
                    otherRevVals.push(
                        OtherRevVals.fromAsn1(oriAsn1 as asn1js.Sequence),
                    )
                }
            }
        }

        return new RevocationValues({
            crlVals: crls,
            ocspVals: ocsps,
            otherRevVals,
        })
    }
}
