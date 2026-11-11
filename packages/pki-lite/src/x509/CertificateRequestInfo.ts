import {
    Asn1Node,
    der,
    keepOriginalDer,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
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
    toAsn1(): Asn1Node {
        // Create the main CertificateRequestInfo sequence
        const values: Asn1Node[] = [
            der.integer(this.version),
            this.subject.toAsn1(),
            this.publicKey.toAsn1(),
        ]

        // attributes [0] is mandatory in PKCS#10 (an empty request writes `A0 00`) and
        // IMPLICIT SET OF: the Attribute elements sit directly inside the [0].
        values.push(
            der.constructed(
                0,
                (this.attributes ?? []).map((attribute: Attribute) =>
                    attribute.toAsn1(),
                ),
            ),
        )

        return der.sequence(values)
    }

    /**
     * Creates a CertificateRequestInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A CertificateRequestInfo
     */
    static fromAsn1(asn1: Asn1Node): CertificateRequestInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.children.length < 3 || asn1.children.length > 4) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 or 4 elements',
            )
        }

        const versionAsn1 = asn1.children[0]
        const subjectAsn1 = asn1.children[1]
        const publicKeyAsn1 = asn1.children[2]
        const attributesAsn1 =
            asn1.children.length > 3 ? asn1.children[3] : undefined

        if (!versionAsn1.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: version must be an INTEGER',
            )
        }

        if (!subjectAsn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: subject must be a SEQUENCE',
            )
        }

        if (!publicKeyAsn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: publicKey must be a SEQUENCE',
            )
        }

        const version = der.readNumber(versionAsn1)
        const subject = RDNSequence.fromAsn1(subjectAsn1)
        const publicKey = SubjectPublicKeyInfo.fromAsn1(publicKeyAsn1)

        let attributes: Attribute[] | undefined

        if (attributesAsn1) {
            // Attributes are [0] context specific, containing a SET OF Attribute
            if (
                !attributesAsn1?.constructed ||
                attributesAsn1.tagClass !== TagClass.Context || // CONTEXT_SPECIFIC
                attributesAsn1.tag !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: attributes must be [0] context specific',
                )
            }

            // The Attribute elements sit directly in the [0]. Older versions of this
            // library wrapped them in an extra SET, so accept that form too.
            const [first] = attributesAsn1.children
            const parsed =
                attributesAsn1.children.length === 1 &&
                first.is(UniversalTag.Set)
                    ? Attributes.fromAsn1(first)
                    : Attributes.fromAsn1(attributesAsn1)
            attributes = parsed.length > 0 ? [...parsed] : undefined
        }

        const requestInfo = new CertificateRequestInfo({
            version,
            subject,
            publicKey,
            attributes,
        })
        // keep the signed bytes: re-encoding may not reproduce them
        keepOriginalDer(requestInfo, asn1)
        return requestInfo
    }
}
