import { Time } from '../asn1/Time.js'
import {
    Asn1Node,
    der,
    keepOriginalDer,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from './Name.js'
import { RevokedCertificate } from './RevokedCertificate.js'
import { Extension } from './Extension.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the "To Be Signed" part of the CRL.
 *
 * @asn
 * ```asn
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                              -- if present, MUST be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                   -- if present, version MUST be v2
 *      } OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                   -- if present, version MUST be v2
 * }
 * ```
 */
export class TBSCertList extends PkiBase<TBSCertList> {
    version?: number
    signature: AlgorithmIdentifier
    issuer: Name
    thisUpdate: Date
    nextUpdate?: Date
    revokedCertificates?: RevokedCertificate[]
    extensions?: Extension[]

    constructor(options: {
        signature: AlgorithmIdentifier
        issuer: Name
        thisUpdate: Date
        nextUpdate?: Date
        revokedCertificates?: RevokedCertificate[]
        extensions?: Extension[]
        version?: 1
    }) {
        super()
        this.signature = options.signature
        this.issuer = options.issuer
        this.thisUpdate = options.thisUpdate
        this.nextUpdate = options.nextUpdate
        this.revokedCertificates = options.revokedCertificates
        this.extensions = options.extensions
        this.version = options.version
    }

    /**
     * Converts the TBSCertList to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        const tbsValues: Asn1Node[] = []

        // Version (optional, default is v1)
        if (this.version !== undefined) {
            tbsValues.push(der.integer(this.version))
        }

        // Signature Algorithm
        tbsValues.push(this.signature.toAsn1())

        // Issuer
        tbsValues.push(this.issuer.toAsn1())

        // ThisUpdate
        tbsValues.push(new Time({ time: this.thisUpdate }).toAsn1())

        // NextUpdate (optional)
        if (this.nextUpdate) {
            tbsValues.push(new Time({ time: this.nextUpdate }).toAsn1())
        }

        // RevokedCertificates (optional)
        if (this.revokedCertificates && this.revokedCertificates.length > 0) {
            const revokedCertsArray = this.revokedCertificates.map((rc) =>
                rc.toAsn1(),
            )

            tbsValues.push(der.sequence(revokedCertsArray))
        }

        // CRL Extensions (optional)
        if (this.extensions && this.extensions.length > 0) {
            const extensionsArray = this.extensions.map((ext) => ext.toAsn1())

            tbsValues.push(der.constructed(0, [der.sequence(extensionsArray)]))
        }

        return der.sequence(tbsValues)
    }

    /**
     * Creates a TBSCertList from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The TBSCertList object
     */
    static fromAsn1(asn1: Asn1Node): TBSCertList {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.children
        if (values.length < 3) {
            // At minimum: signature, issuer, thisUpdate
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 3 elements',
            )
        }

        let index = 0
        let version: number | undefined = undefined

        // Check if first element is version (optional)
        if (values[0]?.is(UniversalTag.Integer)) {
            version = der.readNumber(values[0])
            index++
        }

        // Signature Algorithm
        if (!values[index]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signature',
            )
        }
        const signature = AlgorithmIdentifier.fromAsn1(values[index])
        index++

        // Issuer
        if (!values[index]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for issuer',
            )
        }
        const issuer = Name.fromAsn1(values[index])
        index++

        // ThisUpdate
        const thisUpdate = Time.fromAsn1(values[index], 'thisUpdate').time
        index++

        // NextUpdate (optional)
        let nextUpdate: Date | undefined = undefined
        if (
            index < values.length &&
            (values[index]?.is(UniversalTag.UTCTime) ||
                values[index]?.is(UniversalTag.GeneralizedTime))
        ) {
            nextUpdate = Time.fromAsn1(values[index], 'nextUpdate').time
            index++
        }

        // RevokedCertificates (optional)
        let revokedCertificates: RevokedCertificate[] | undefined = undefined
        if (index < values.length && values[index]?.is(UniversalTag.Sequence)) {
            const revokedCertsAsn1 = values[index].children
            revokedCertificates = revokedCertsAsn1.map((cert) =>
                RevokedCertificate.fromAsn1(cert),
            )
            index++
        }

        // CRL Extensions (optional)
        let extensions: Extension[] | undefined = undefined
        if (
            index < values.length &&
            !!values[index]?.constructed &&
            values[index].tagClass === TagClass.Context &&
            values[index].tag === 0
        ) {
            const extSeq = values[index].children[0]
            if (!extSeq.is(UniversalTag.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected SEQUENCE for extensions',
                )
            }

            const extensionsAsn1 = extSeq.children
            extensions = extensionsAsn1.map((ext) => Extension.fromAsn1(ext))
        }

        if (version !== 1 && version !== undefined) {
            throw new Asn1ParseError(
                'Unsupported version: only v1 (0) is supported',
            )
        }

        const tbsCertList = new TBSCertList({
            signature,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates,
            extensions,
            version,
        })
        // keep the signed bytes: re-encoding may not reproduce them
        keepOriginalDer(tbsCertList, asn1)
        return tbsCertList
    }
}
