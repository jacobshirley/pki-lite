import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Attribute } from './Attribute.js'
import { RDNSequence } from './RDNSequence.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Attributes } from './Attributes.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the inner info of a PKCS#10 certificate request.
 *
 * @asn
 * ```asn
 * CertificationRequestInfo ::= SEQUENCE {
 *      version       INTEGER { v1(0) } (v1,...),
 *      subject       Name,
 *      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *      attributes    [0] Attributes{{ CRIAttributes }}
 * }
 *
 * Name ::= RDNSequence
 * ```
 */
export class CertificateRequestInfo extends PkiBase<CertificateRequestInfo> {
    version: number
    subject: RDNSequence
    publicKey: SubjectPublicKeyInfo
    attributes?: Attributes

    constructor(options: {
        version: number
        subject: RDNSequence
        publicKey: SubjectPublicKeyInfo
        attributes?: Attribute[]
    }) {
        super()

        this.version = options.version
        this.subject = options.subject
        this.publicKey = options.publicKey
        this.attributes = options.attributes?.length
            ? new Attributes(...options.attributes)
            : undefined
    }

    /**
     * Converts the certificate request info to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        // Create the main CertificateRequestInfo sequence
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            this.subject.toAsn1(),
            this.publicKey.toAsn1(),
        ]

        // attributes [0] is mandatory in PKCS#10 (an empty request writes `A0 00`) and
        // IMPLICIT SET OF: the Attribute elements sit directly inside the [0].
        values.push(
            new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT_SPECIFIC
                    tagNumber: 0, // [0]
                },
                value: (this.attributes ?? []).map((attribute: Attribute) =>
                    attribute.toAsn1(),
                ),
            }),
        )

        return new asn1js.Sequence({
            value: values,
        })
    }

    /**
     * Creates a CertificateRequestInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A CertificateRequestInfo
     */
    static fromAsn1(asn1: Asn1BaseBlock): CertificateRequestInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (
            asn1.valueBlock.value.length < 3 ||
            asn1.valueBlock.value.length > 4
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 or 4 elements',
            )
        }

        const versionAsn1 = asn1.valueBlock.value[0]
        const subjectAsn1 = asn1.valueBlock.value[1]
        const publicKeyAsn1 = asn1.valueBlock.value[2]
        const attributesAsn1 =
            asn1.valueBlock.value.length > 3
                ? asn1.valueBlock.value[3]
                : undefined

        if (!(versionAsn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: version must be an INTEGER',
            )
        }

        if (!(subjectAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: subject must be a SEQUENCE',
            )
        }

        if (!(publicKeyAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: publicKey must be a SEQUENCE',
            )
        }

        const version = versionAsn1.valueBlock.valueDec
        const subject = RDNSequence.fromAsn1(subjectAsn1)
        const publicKey = SubjectPublicKeyInfo.fromAsn1(publicKeyAsn1)

        let attributes: Attribute[] | undefined

        if (attributesAsn1) {
            // Attributes are [0] context specific, containing a SET OF Attribute
            if (
                !(attributesAsn1 instanceof asn1js.Constructed) ||
                attributesAsn1.idBlock.tagClass !== 3 || // CONTEXT_SPECIFIC
                attributesAsn1.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: attributes must be [0] context specific',
                )
            }

            // The Attribute elements sit directly in the [0]. Older versions of this
            // library wrapped them in an extra SET, so accept that form too.
            const [first] = attributesAsn1.valueBlock.value
            const parsed =
                attributesAsn1.valueBlock.value.length === 1 &&
                first instanceof asn1js.Set
                    ? Attributes.fromAsn1(first)
                    : Attributes.fromAsn1(attributesAsn1)
            attributes = parsed.length > 0 ? [...parsed] : undefined
        }

        return new CertificateRequestInfo({
            version,
            subject,
            publicKey,
            attributes,
        })
    }
}
