import { Time } from '../asn1/Time.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'
import { Extension } from './Extension.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { Integer } from '../asn1/Integer.js'
import { OIDs } from '../core/OIDs.js'
import { CRLReason } from './CRLReason.js'
import { GeneralNames } from './GeneralName.js'

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
     * The serial number as a bigint. A string `userCertificate` is read as hex;
     * separators such as `:` and a `0x` prefix are ignored.
     */
    serialAsBigInt(): bigint {
        if (typeof this.userCertificate === 'number') {
            return BigInt(this.userCertificate)
        }
        const hex = this.userCertificate
            .replace(/^0x/i, '')
            .replace(/[^0-9a-f]/gi, '')
        if (hex.length === 0) {
            throw new Asn1ParseError(
                `Invalid serial number: ${this.userCertificate}`,
            )
        }
        return BigInt('0x' + hex)
    }

    /**
     * The revocation reason code from the entry's reasonCode extension (RFC 5280 5.3.1:
     * 1 keyCompromise, 6 certificateHold, 8 removeFromCRL, ...), if it has one.
     */
    get reason(): number | undefined {
        return this.extension(
            OIDs.EXTENSION.CRL_REASON_CODE,
        )?.extnValue.parseAs(CRLReason).value
    }

    /**
     * The certificateIssuer extension of an entry on an indirect CRL (RFC 5280 5.3.3): the
     * issuer of the certificates from this entry on, until another entry names another.
     */
    get certificateIssuer(): GeneralNames | undefined {
        return this.extension(
            OIDs.EXTENSION.CERTIFICATE_ISSUER,
        )?.extnValue.parseAs(GeneralNames)
    }

    private extension(oid: string): Extension | undefined {
        return this.crlEntryExtensions?.find(
            (extension) => extension.extnID.value === oid,
        )
    }

    /**
     * Converts the revoked certificate to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        // Serial number, exact for serials of any size
        values.push(new Integer({ value: this.serialAsBigInt() }).toAsn1())

        // Revocation Date
        values.push(new Time({ time: this.revocationDate }).toAsn1())

        // CRL Entry Extensions (optional)
        if (this.crlEntryExtensions && this.crlEntryExtensions.length > 0) {
            const extArray = this.crlEntryExtensions.map((ext) => ext.toAsn1())

            values.push(der.sequence(extArray))
        }

        return der.sequence(values)
    }

    /**
     * Creates a RevokedCertificate from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A RevokedCertificate
     */
    static fromAsn1(asn1: Asn1Node): RevokedCertificate {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.children.length < 2 || asn1.children.length > 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 or 3 elements',
            )
        }

        const userCertificateAsn1 = asn1.children[0]
        const revocationDateAsn1 = asn1.children[1]
        const crlEntryExtensionsAsn1 =
            asn1.children.length > 2 ? asn1.children[2] : undefined

        if (!userCertificateAsn1.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: userCertificate must be an INTEGER',
            )
        }

        // A number when it is exactly representable, otherwise a hex string
        const serial = Integer.fromAsn1(userCertificateAsn1).toBigInt()
        const userCertificate =
            serial >= BigInt(Number.MIN_SAFE_INTEGER) &&
            serial <= BigInt(Number.MAX_SAFE_INTEGER)
                ? Number(serial)
                : serial.toString(16)

        // Get the revocation date
        const revocationDate = Time.fromAsn1(
            revocationDateAsn1,
            'revocationDate',
        ).time

        // Parse optional extensions
        let crlEntryExtensions: Extension[] | undefined

        if (crlEntryExtensionsAsn1) {
            if (!crlEntryExtensionsAsn1.is(UniversalTag.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: crlEntryExtensions must be a SEQUENCE',
                )
            }

            crlEntryExtensions = crlEntryExtensionsAsn1.children.map(
                (extensionAsn1: Asn1Node) => {
                    if (!extensionAsn1.is(UniversalTag.Sequence)) {
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
