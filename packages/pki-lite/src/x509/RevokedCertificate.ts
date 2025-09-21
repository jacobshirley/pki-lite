import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Extension } from './Extension.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a revoked certificate entry in a CRL.
 *
 * @asn
 * ```asn
 * RevokedCertificate  ::=  SEQUENCE  {
 *      userCertificate         CertificateSerialNumber,
 *      revocationDate          Time,
 *      crlEntryExtensions      Extensions OPTIONAL
 *                             -- if present, version MUST be v2
 * }
 * ```
 */
export class RevokedCertificate extends PkiBase<RevokedCertificate> {
    userCertificate: number | string
    revocationDate: Date
    crlEntryExtensions?: Extension[]

    constructor(options: {
        userCertificate: number | string
        revocationDate: Date
        crlEntryExtensions?: Extension[]
    }) {
        super()
        this.userCertificate = options.userCertificate
        this.revocationDate = options.revocationDate
        this.crlEntryExtensions = options.crlEntryExtensions
    }

    /**
     * Converts the revoked certificate to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []

        // Serial Number - Convert string to number if necessary
        const serialValue =
            typeof this.userCertificate === 'string'
                ? parseInt(this.userCertificate, 16) // Parse as hex since certificate serial numbers are typically hex
                : this.userCertificate

        values.push(
            new asn1js.Integer({
                value: serialValue,
            }),
        )

        // Revocation Date
        values.push(
            new asn1js.UTCTime({
                valueDate: this.revocationDate,
            }),
        )

        // CRL Entry Extensions (optional)
        if (this.crlEntryExtensions && this.crlEntryExtensions.length > 0) {
            const extArray = this.crlEntryExtensions.map((ext) => ext.toAsn1())

            values.push(
                new asn1js.Sequence({
                    value: extArray,
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a RevokedCertificate from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A RevokedCertificate
     */
    static fromAsn1(asn1: Asn1BaseBlock): RevokedCertificate {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (
            asn1.valueBlock.value.length < 2 ||
            asn1.valueBlock.value.length > 3
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 or 3 elements',
            )
        }

        const userCertificateAsn1 = asn1.valueBlock.value[0]
        const revocationDateAsn1 = asn1.valueBlock.value[1]
        const crlEntryExtensionsAsn1 =
            asn1.valueBlock.value.length > 2
                ? asn1.valueBlock.value[2]
                : undefined

        if (!(userCertificateAsn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: userCertificate must be an INTEGER',
            )
        }

        // Convert serial number to string or number
        const userCertificate = userCertificateAsn1.valueBlock
            .toString()
            .includes('0x')
            ? userCertificateAsn1.valueBlock.toString()
            : userCertificateAsn1.valueBlock.valueDec

        // Get the revocation date
        let revocationDate: Date

        if (revocationDateAsn1 instanceof asn1js.UTCTime) {
            revocationDate = revocationDateAsn1.toDate()
        } else if (revocationDateAsn1 instanceof asn1js.GeneralizedTime) {
            revocationDate = revocationDateAsn1.toDate()
        } else {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: revocationDate must be a UTCTime or GeneralizedTime',
            )
        }

        // Parse optional extensions
        let crlEntryExtensions: Extension[] | undefined

        if (crlEntryExtensionsAsn1) {
            if (!(crlEntryExtensionsAsn1 instanceof asn1js.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: crlEntryExtensions must be a SEQUENCE',
                )
            }

            crlEntryExtensions = crlEntryExtensionsAsn1.valueBlock.value.map(
                (extensionAsn1: Asn1BaseBlock) => {
                    if (!(extensionAsn1 instanceof asn1js.Sequence)) {
                        throw new Asn1ParseError(
                            'Invalid ASN. ASN.1 structure: extension must be a SEQUENCE',
                        )
                    }
                    return Extension.fromAsn1(extensionAsn1)
                },
            )
        }

        return new RevokedCertificate({
            userCertificate,
            revocationDate,
            crlEntryExtensions,
        })
    }
}
