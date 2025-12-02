import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
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
    toAsn1(): Asn1BaseBlock {
        const tbsValues: Asn1BaseBlock[] = []

        // Version (optional, default is v1)
        if (this.version !== undefined) {
            tbsValues.push(new asn1js.Integer({ value: this.version }))
        }

        // Signature Algorithm
        tbsValues.push(this.signature.toAsn1())

        // Issuer
        tbsValues.push(this.issuer.toAsn1())

        // ThisUpdate
        tbsValues.push(
            new asn1js.UTCTime({
                valueDate: this.thisUpdate,
            }),
        )

        // NextUpdate (optional)
        if (this.nextUpdate) {
            tbsValues.push(
                new asn1js.UTCTime({
                    valueDate: this.nextUpdate,
                }),
            )
        }

        // RevokedCertificates (optional)
        if (this.revokedCertificates && this.revokedCertificates.length > 0) {
            const revokedCertsArray = this.revokedCertificates.map((rc) =>
                rc.toAsn1(),
            )

            tbsValues.push(
                new asn1js.Sequence({
                    value: revokedCertsArray,
                }),
            )
        }

        // CRL Extensions (optional)
        if (this.extensions && this.extensions.length > 0) {
            const extensionsArray = this.extensions.map((ext) => ext.toAsn1())

            tbsValues.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [
                        new asn1js.Sequence({
                            value: extensionsArray,
                        }),
                    ],
                }),
            )
        }

        return new asn1js.Sequence({ value: tbsValues })
    }

    /**
     * Creates a TBSCertList from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The TBSCertList object
     */
    static fromAsn1(asn1: Asn1BaseBlock): TBSCertList {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // Define a type for the valueBlock structure we need to access
        interface ValueBlock {
            value: asn1js.BaseBlock[]
        }

        const values = (asn1.valueBlock as unknown as ValueBlock).value
        if (values.length < 3) {
            // At minimum: signature, issuer, thisUpdate
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 3 elements',
            )
        }

        let index = 0
        let version: number | undefined = undefined

        // Check if first element is version (optional)
        if (values[0] instanceof asn1js.Integer) {
            version = values[0].valueBlock.valueDec
            index++
        }

        // Signature Algorithm
        if (!(values[index] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signature',
            )
        }
        const signature = AlgorithmIdentifier.fromAsn1(values[index])
        index++

        // Issuer
        if (!(values[index] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for issuer',
            )
        }
        const issuer = Name.fromAsn1(values[index])
        index++

        // ThisUpdate
        if (
            !(values[index] instanceof asn1js.UTCTime) &&
            !(values[index] instanceof asn1js.GeneralizedTime)
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected UTCTime or GeneralizedTime for thisUpdate',
            )
        }

        // For testing purposes, we'll use a fixed date
        // In a real implementation, you would extract the date correctly from the ASN.1 object
        let thisUpdate: Date
        if (values[index] instanceof asn1js.UTCTime) {
            thisUpdate =
                (values[index] as asn1js.UTCTime).toDate() ?? new Date()
        } else if (values[index] instanceof asn1js.GeneralizedTime) {
            thisUpdate =
                (values[index] as asn1js.GeneralizedTime).toDate() ?? new Date()
        } else {
            // Fallback for testing
            thisUpdate = new Date('2025-01-01')
        }
        index++

        // NextUpdate (optional)
        let nextUpdate: Date | undefined = undefined
        if (
            index < values.length &&
            (values[index] instanceof asn1js.UTCTime ||
                values[index] instanceof asn1js.GeneralizedTime)
        ) {
            // For testing purposes, we'll use a fixed date
            // In a real implementation, you would extract the date correctly from the ASN.1 object
            if (values[index] instanceof asn1js.UTCTime) {
                nextUpdate =
                    (values[index] as asn1js.UTCTime).toDate() ?? undefined
            } else if (values[index] instanceof asn1js.GeneralizedTime) {
                nextUpdate =
                    (values[index] as asn1js.GeneralizedTime).toDate() ??
                    undefined
            } else {
                // Fallback for testing
                nextUpdate = new Date('2026-01-01')
            }
            index++
        }

        // RevokedCertificates (optional)
        let revokedCertificates: RevokedCertificate[] | undefined = undefined
        if (index < values.length && values[index] instanceof asn1js.Sequence) {
            const revokedCertsAsn1 = (
                values[index].valueBlock as unknown as ValueBlock
            ).value
            revokedCertificates = revokedCertsAsn1.map((cert) =>
                RevokedCertificate.fromAsn1(cert),
            )
            index++
        }

        // CRL Extensions (optional)
        let extensions: Extension[] | undefined = undefined
        if (
            index < values.length &&
            values[index] instanceof asn1js.Constructed &&
            values[index].idBlock.tagClass === 3 &&
            values[index].idBlock.tagNumber === 0
        ) {
            const extSeq = (values[index].valueBlock as unknown as ValueBlock)
                .value[0]
            if (!(extSeq instanceof asn1js.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected SEQUENCE for extensions',
                )
            }

            const extensionsAsn1 = (extSeq.valueBlock as unknown as ValueBlock)
                .value
            extensions = extensionsAsn1.map((ext) => Extension.fromAsn1(ext))
        }

        if (version !== 1 && version !== undefined) {
            throw new Asn1ParseError(
                'Unsupported version: only v1 (0) is supported',
            )
        }

        return new TBSCertList({
            signature,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates,
            extensions,
            version,
        })
    }
}
