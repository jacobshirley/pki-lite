import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    UniversalTag,
} from '../core/PkiBase.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { CertificateList } from '../x509/CertificateList.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OtherRevInfo } from './OtherRevInfo.js'

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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        if (this.crls && this.crls.length > 0) {
            const crlSeq = der.sequence(this.crls.map((crl) => crl.toAsn1()))
            values.push(der.constructed(0, [crlSeq]))
        }

        if (this.ocsps && this.ocsps.length > 0) {
            const ocspSeq = der.sequence(
                this.ocsps.map((ocsp) => ocsp.toAsn1()),
            )
            values.push(der.constructed(1, [ocspSeq]))
        }

        if (this.otherRevInfo && this.otherRevInfo.length > 0) {
            const otherRevInfoSeq = der.sequence(
                this.otherRevInfo.map((ori) => ori.toAsn1()),
            )
            values.push(der.constructed(2, [otherRevInfoSeq]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): RevocationInfoArchival {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const crls: CertificateList[] = []
        const ocsps: OCSPResponse[] = []
        const otherRevInfo: OtherRevInfo[] = []

        for (const element of asn1.children) {
            if (!element?.constructed) {
                continue
            }

            const tagNumber = element.tag

            if (tagNumber === 0) {
                const crlSeq = element.children[0]

                if (!crlSeq.is(UniversalTag.Sequence)) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure for CRL sequence',
                    )
                }

                for (const crlAsn1 of crlSeq.children) {
                    crls.push(CertificateList.fromAsn1(crlAsn1))
                }
            } else if (tagNumber === 1) {
                const ocspSeq = element.children[0]

                if (!ocspSeq.is(UniversalTag.Sequence)) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure for OCSP sequence',
                    )
                }

                for (const ocspAsn1 of ocspSeq.children) {
                    ocsps.push(OCSPResponse.fromAsn1(ocspAsn1))
                }
            } else if (tagNumber === 2) {
                const oriSeq = element.children[0]

                if (!oriSeq.is(UniversalTag.Sequence)) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure for OtherRevInfo sequence',
                    )
                }

                for (const oriAsn1 of oriSeq.children) {
                    if (!oriAsn1.is(UniversalTag.Sequence)) {
                        throw new Asn1ParseError(
                            'Invalid ASN.1 structure for OtherRevInfo item',
                        )
                    }

                    otherRevInfo.push(OtherRevInfo.fromAsn1(oriAsn1))
                }
            }
        }

        return new RevocationInfoArchival({ crls, ocsps, otherRevInfo })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): RevocationInfoArchival {
        return RevocationInfoArchival.fromAsn1(derToAsn1(der))
    }
}
