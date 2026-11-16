import { Any } from '../../asn1/Any.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import {
    Asn1Any,
    Asn1Node,
    der,
    ObjectIdentifierString,
    PkiBase,
    UniversalTag,
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
        return der.sequence([
            this.OtherRevValType.toAsn1(),
            this.OtherRevVals.toAsn1(),
        ])
    }

    static fromAsn1(asn1: Asn1Node): OtherRevVals {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }
        const type = asn1.children[0]
        const value = asn1.children[1]

        return new OtherRevVals({
            OtherRevValType: der.readOid(type),
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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        if (this.crlVals && this.crlVals.length > 0) {
            const crlSeq = der.sequence(this.crlVals.map((crl) => crl.toAsn1()))
            values.push(der.constructed(0, [crlSeq]))
        }

        if (this.ocspVals && this.ocspVals.length > 0) {
            const ocspSeq = der.sequence(
                this.ocspVals.map((ocsp) => ocsp.toAsn1()),
            )
            values.push(der.constructed(1, [ocspSeq]))
        }

        if (this.otherRevVals && this.otherRevVals.length > 0) {
            const otherRevValsSeq = der.sequence(
                this.otherRevVals.map((ori) => ori.toAsn1()),
            )
            values.push(der.constructed(2, [otherRevValsSeq]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): RevocationValues {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const crls: CertificateList[] = []
        const ocsps: BasicOCSPResponse[] = []
        const otherRevVals: OtherRevVals[] = []

        for (const element of asn1.children) {
            if (!element?.constructed) {
                continue
            }

            const tagNumber = element.tag

            if (tagNumber === 0) {
                const crlSeq = element.children[0]
                for (const crlAsn1 of crlSeq.children) {
                    crls.push(CertificateList.fromAsn1(crlAsn1))
                }
            } else if (tagNumber === 1) {
                const ocspSeq = element.children[0]
                for (const ocspAsn1 of ocspSeq.children) {
                    ocsps.push(BasicOCSPResponse.fromAsn1(ocspAsn1))
                }
            } else if (tagNumber === 2) {
                const oriSeq = element.children[0]
                for (const oriAsn1 of oriSeq.children) {
                    otherRevVals.push(OtherRevVals.fromAsn1(oriAsn1))
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
