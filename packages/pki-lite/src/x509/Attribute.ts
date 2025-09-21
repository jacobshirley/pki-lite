import {
    OtherRevInfo,
    RevocationInfoArchival,
} from '../adobe/RevocationInfoArchival.js'
import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { UTCTime } from '../asn1/UTCTime.js'
import { OIDs } from '../core/OIDs.js'
import {
    Asn1BaseBlock,
    Asn1Any,
    asn1js,
    PkiBase,
    ObjectIdentifierString,
    derToAsn1,
} from '../core/PkiBase.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'
import { RevocationValues } from './attributes/RevocationValues.js'
import { SignaturePolicyId } from './attributes/SignaturePolicyIdentifier.js'
import { SignerLocation } from './attributes/SignerLocation.js'
import { SigningCertificate } from './attributes/SigningCertificate.js'
import { SigningCertificateV2 } from './attributes/SigningCertificateV2.js'
import { CertificateList } from './CertificateList.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an attribute structure used in PKCS#7 and PKCS#10.
 *
 * @asn
 * ```asn
 * Attribute ::= SEQUENCE {
 *      type OBJECT IDENTIFIER,
 *      values SET OF AttributeValue
 * }
 *
 * AttributeValue ::= ANY
 * ```
 */
export class Attribute extends PkiBase<Attribute> {
    type: ObjectIdentifier
    values: Any[]

    /**
     * Creates a new attribute.
     */
    constructor(options: { type: ObjectIdentifierString; values: Asn1Any[] }) {
        super()

        const { type, values } = options

        this.type = new ObjectIdentifier({ value: type })
        this.values = values.map((value) => new Any({ derBytes: value }))
    }

    /**
     * Converts the attribute to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.type.toAsn1(),
                new asn1js.Set({
                    value: this.values.map((value) => value.toAsn1()),
                }),
            ],
        })
    }

    /**
     * Creates an Attribute from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The attribute
     */
    static fromAsn1(asn1: Asn1BaseBlock): Attribute {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE but got ' +
                    asn1.constructor.name,
            )
        }

        if (asn1.valueBlock.value.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements',
            )
        }

        const [typeAsn1, valuesAsn1] = asn1.valueBlock.value

        if (!(typeAsn1 instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
            )
        }

        if (!(valuesAsn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError('Invalid ASN.1 structure: expected SET')
        }

        const type = typeAsn1.valueBlock.toString()
        const values: Asn1Any[] = valuesAsn1.valueBlock.value.map(
            (x) => new Any({ derBytes: x }),
        )

        return new Attribute({
            type,
            values,
        })
    }

    static fromDER(der: ArrayBuffer | Uint8Array): Attribute {
        return Attribute.fromAsn1(derToAsn1(der))
    }

    static signingTime(date: Date): Attribute {
        const time = new UTCTime({ time: date })

        return new Attribute({
            type: OIDs.PKCS9.SIGNING_TIME,
            values: [time],
        })
    }

    static contentType(
        oid: ObjectIdentifierString | ObjectIdentifier,
    ): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.CONTENT_TYPE,
            values: [new ObjectIdentifier({ value: oid })],
        })
    }

    static messageDigest(digest: ArrayBuffer | Uint8Array): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.MESSAGE_DIGEST,
            values: [new OctetString({ bytes: new Uint8Array(digest) })],
        })
    }

    static signingCertificate(certificate: SigningCertificate): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.ETS_SIGNING_CERTIFICATE,
            values: [certificate],
        })
    }

    static signingCertificateV2(certificate: SigningCertificateV2): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.ETS_SIGNING_CERTIFICATE_V2,
            values: [certificate],
        })
    }

    static timestampToken(token: ContentInfo): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.TIME_STAMP_TOKEN,
            values: [token],
        })
    }

    static signingLocation(options: {
        countryName?: string
        localityName?: string
        postalAddress?: string[] | string
    }): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.ETS_SIGNING_LOCATION,
            values: [SignerLocation.create(options)],
        })
    }

    static commitmentTypeIndication(reason: string): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.ETS_COMMITMENT_TYPE_INDICATION,
            values: [new asn1js.Utf8String({ value: reason })],
        })
    }

    static signaturePolicyIdentifier(
        signaturePolicyId: SignaturePolicyId,
    ): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.ETS_SIGNATURE_POLICY_IDENTIFIER,
            values: [signaturePolicyId],
        })
    }

    static revocationValues(options: RevocationValues): Attribute {
        return new Attribute({
            type: OIDs.PKCS9.ETS_REVOCATION_VALUES,
            values: [options],
        })
    }

    static adobeRevocationInfoArchival(
        revocationInfoArchival: RevocationInfoArchival,
    ): Attribute {
        return new Attribute({
            type: OIDs.ADOBE.REVOCATION_INFO_ARCHIVAL,
            values: [revocationInfoArchival.toAsn1()],
        })
    }
}
