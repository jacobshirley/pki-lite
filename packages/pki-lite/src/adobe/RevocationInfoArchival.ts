import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Asn1Any, Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { CertificateList } from '../x509/CertificateList.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the OtherRevInfo structure used in RevocationInfoArchival.
 *
 * @asn
 * ```asn
 * OtherRevInfo ::= SEQUENCE {
 *   Type  OBJECT IDENTIFIER
 *   Value OCTET STRING
 * }
 * ```
 */
export class OtherRevInfo extends PkiBase<OtherRevInfo> {
    type: ObjectIdentifier
    value: Any

    constructor(options: { type: string; value: Asn1Any }) {
        super()
        this.type = new ObjectIdentifier({ value: options.type })
        this.value = new Any({ derBytes: options.value })
    }

    toAsn1(): asn1js.Sequence {
        return new asn1js.Sequence({
            value: [this.type.toAsn1(), this.value.toAsn1()],
        })
    }

    static fromAsn1(asn1: asn1js.Sequence): OtherRevInfo {
        const type = asn1.valueBlock.value[0] as asn1js.ObjectIdentifier
        const value = asn1.valueBlock.value[1]

        return new OtherRevInfo({
            type: type.valueBlock.toString(),
            value: new Any({ derBytes: value }),
        })
    }
}

/**
 * Represents the RevocationInfoArchival attribute defined by Adobe.
 *
 * @asn
 * ```asn
 * adbe-revocationInfoArchival OBJECT IDENTIFIER ::=
 *   {adbe(1.2.840.113583) acrobat(1) security(1) 8}
 *
 * RevocationInfoArchival ::= SEQUENCE {
 *   crl  [0] EXPLICIT SEQUENCE of CRLs OPTIONAL
 *   ocsp  [1] EXPLICIT SEQUENCE of OCSPResponse OPTIONAL
 *   otherRevInfo [2] EXPLICIT SEQUENCE of OtherRevInfo OPTIONAL
 * }
 * ```
 */
export class RevocationInfoArchival extends PkiBase<RevocationInfoArchival> {
    crls?: CertificateList[]
    ocsps?: OCSPResponse[]
    otherRevInfo?: OtherRevInfo[]

    constructor(options: {
        crls?: CertificateList[]
        ocsps?: OCSPResponse[]
        otherRevInfo?: OtherRevInfo[]
    }) {
        super()
        this.crls = options.crls
        this.ocsps = options.ocsps
        this.otherRevInfo = options.otherRevInfo
    }

    toAsn1(): asn1js.Sequence {
        const values: asn1js.Constructed[] = []

        if (this.crls && this.crls.length > 0) {
            const crlSeq = new asn1js.Sequence({
                value: this.crls.map((crl) => crl.toAsn1()),
            })
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [crlSeq],
                }),
            )
        }

        if (this.ocsps && this.ocsps.length > 0) {
            const ocspSeq = new asn1js.Sequence({
                value: this.ocsps.map((ocsp) => ocsp.toAsn1()),
            })
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 },
                    value: [ocspSeq],
                }),
            )
        }

        if (this.otherRevInfo && this.otherRevInfo.length > 0) {
            const otherRevInfoSeq = new asn1js.Sequence({
                value: this.otherRevInfo.map((ori) => ori.toAsn1()),
            })
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 },
                    value: [otherRevInfoSeq],
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): RevocationInfoArchival {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const crls: CertificateList[] = []
        const ocsps: OCSPResponse[] = []
        const otherRevInfo: OtherRevInfo[] = []

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
                        OCSPResponse.fromAsn1(ocspAsn1 as asn1js.Sequence),
                    )
                }
            } else if (tagNumber === 2) {
                const oriSeq = element.valueBlock.value[0] as asn1js.Sequence
                for (const oriAsn1 of oriSeq.valueBlock.value) {
                    otherRevInfo.push(
                        OtherRevInfo.fromAsn1(oriAsn1 as asn1js.Sequence),
                    )
                }
            }
        }

        return new RevocationInfoArchival({ crls, ocsps, otherRevInfo })
    }
}
