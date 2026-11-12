import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    PkiSet,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'
import { Attribute } from '../x509/Attribute.js'
import { SignerIdentifier } from './SignerIdentifier.js'
import { CMSVersion } from './CMSVersion.js'
import { Attributes } from '../x509/Attributes.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OIDs } from '../core/OIDs.js'
import { OctetString } from '../asn1/OctetString.js'

/**
 * Represents a set of unsigned attributes.
 *
 * This class is used to group together attributes that are not signed.
 *
 * @asn
 * ```asn
 * UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
export class UnsignedAttributes extends Attributes {
    static fromAsn1(asn1: Asn1Node): UnsignedAttributes {
        return new UnsignedAttributes(...super.fromAsn1(asn1))
    }
}

/**
 * Represents a set of signed attributes.
 *
 * This class is used to group together attributes that are signed.
 *
 * @asn
 * ```asn
 * SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
export class SignedAttributes extends Attributes {
    static fromAsn1(asn1: Asn1Node): SignedAttributes {
        return new SignedAttributes(...super.fromAsn1(asn1))
    }
}

/**
 * Represents a CMS SignerInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * SignerInfo ::= SEQUENCE {
 *      version CMSVersion,
 *      sid SignerIdentifier,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *      signatureAlgorithm SignatureAlgorithmIdentifier,
 *      signature SignatureValue,
 *      unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
 * }
 *
 * SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
 * SignatureValue ::= OCTET STRING
 * SubjectKeyIdentifier ::= OCTET STRING
 * ```
 */

export class SignerInfo extends PkiBase<SignerInfo> {
    static SignedAttributes = SignedAttributes
    static UnsignedAttributes = UnsignedAttributes

    version: CMSVersion
    sid: SignerIdentifier
    digestAlgorithm: DigestAlgorithmIdentifier
    signedAttrs?: SignedAttributes
    signatureAlgorithm: SignatureAlgorithmIdentifier
    signature: Uint8Array<ArrayBuffer>
    unsignedAttrs?: UnsignedAttributes

    constructor(options: {
        version: CMSVersion
        sid: SignerIdentifier
        digestAlgorithm: AlgorithmIdentifier
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array<ArrayBuffer>
        signedAttrs?: Attribute[]
        unsignedAttrs?: Attribute[]
    }) {
        super()

        const {
            version,
            sid,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
            unsignedAttrs,
        } = options

        this.version = version
        this.sid = sid
        this.digestAlgorithm = new DigestAlgorithmIdentifier(digestAlgorithm)
        this.signatureAlgorithm = new SignatureAlgorithmIdentifier(
            signatureAlgorithm,
        )
        this.signature = signature
        this.signedAttrs = signedAttrs?.length
            ? new SignedAttributes(...signedAttrs)
            : undefined
        this.unsignedAttrs = unsignedAttrs?.length
            ? new UnsignedAttributes(...unsignedAttrs)
            : undefined
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [der.integer(this.version)]

        let signerIdAsn1 = this.sid.toAsn1()
        // Add the SignerIdentifier (CHOICE)
        if (!(this.sid instanceof IssuerAndSerialNumber)) {
            // subjectKeyIdentifier [0] IMPLICIT SubjectKeyIdentifier
            signerIdAsn1 = signerIdAsn1.implicit(0) // [0] IMPLICIT
        }
        values.push(signerIdAsn1)

        values.push(this.digestAlgorithm.toAsn1())

        // SignedAttrs [0] IMPLICIT (optional)
        if (this.signedAttrs && this.signedAttrs.length > 0) {
            const attributesAsn1 = this.signedAttrs.toAsn1().implicit(0) // [0] IMPLICIT

            values.push(attributesAsn1)
        }

        values.push(
            this.signatureAlgorithm.toAsn1(),
            der.octetString(this.signature),
        )

        // UnsignedAttrs [1] IMPLICIT (optional)
        if (this.unsignedAttrs && this.unsignedAttrs.length > 0) {
            const attributesAsn1 = this.unsignedAttrs.toAsn1().implicit(1) // [1] IMPLICIT

            values.push(attributesAsn1)
        }

        return der.sequence(values)
    }

    /**
     * Creates a SignerInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A SignerInfo object
     */
    static fromAsn1(asn1: Asn1Node): SignerInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.children
        if (values.length < 5) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 5 elements, got ${values.length}`,
            )
        }

        let index = 0

        // Version
        if (!values[index]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = der.readNumber(values[index])
        index++

        // SignerIdentifier (CHOICE)
        const sid = SignerIdentifier.fromAsn1(values[index])
        index++

        // DigestAlgorithm
        const digestAlgorithm = AlgorithmIdentifier.fromAsn1(values[index])
        index++

        // SignedAttrs (optional)
        let signedAttrs: Attribute[] | undefined = undefined
        if (
            index < values.length &&
            values[index].tagClass === TagClass.Context && // CONTEXT-SPECIFIC
            values[index].tag === 0 // [0]
        ) {
            signedAttrs = SignedAttributes.fromAsn1(values[index])
            index++
        }

        // SignatureAlgorithm
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[index])
        index++

        // Signature
        if (!values[index]?.is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for signature',
            )
        }
        const signature = new Uint8Array(values[index].bytes())
        index++

        // UnsignedAttrs (optional)
        let unsignedAttrs: Attribute[] | undefined = undefined
        if (
            index < values.length &&
            values[index].tagClass === TagClass.Context && // CONTEXT-SPECIFIC
            values[index].tag === 1 // [1]
        ) {
            unsignedAttrs = UnsignedAttributes.fromAsn1(values[index])
            index++
        }

        return new SignerInfo({
            version,
            sid,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
            unsignedAttrs,
        })
    }

    static fromDer(derBytes: Uint8Array<ArrayBuffer>): SignerInfo {
        return SignerInfo.fromAsn1(derToAsn1(derBytes))
    }

    private getSignatureData(
        data?: Uint8Array<ArrayBuffer>,
    ): Uint8Array<ArrayBuffer> {
        if (this.signedAttrs) {
            // When signed attributes are present, the signature is computed over the
            // DER encoding of the SignedAttributes value
            const asn1 = this.signedAttrs.toAsn1()
            return asn1.encode()
        }

        if (data) {
            // When no signed attributes are present, the signature is computed over the data
            return data
        }

        throw new Error(
            'No signed attributes present and no data provided for signature verification',
        )
    }

    /**
     * The algorithm to verify the signature with.
     *
     * RFC 5652 5.3 and RFC 3370 3.2: RSA PKCS#1 v1.5 signatures are identified by
     * `rsaEncryption` alone (this is what OpenSSL and most CMS writers emit); the hash is
     * the one named by `digestAlgorithm`. Combine them into the explicit
     * `shaNWithRSAEncryption` form that the crypto provider understands.
     */
    private getVerificationAlgorithm(): SignatureAlgorithmIdentifier {
        if (this.signatureAlgorithm.algorithm.value === OIDs.RSA.ENCRYPTION) {
            return AlgorithmIdentifier.signatureAlgorithm({
                type: 'RSASSA_PKCS1_v1_5',
                params: { hash: this.digestAlgorithm.toHashAlgorithm() },
            })
        }
        return this.signatureAlgorithm
    }

    async verify(options: {
        data: Uint8Array<ArrayBuffer>
        publicKeyInfo: SubjectPublicKeyInfo
    }): Promise<
        | {
              valid: true
          }
        | {
              valid: false
              reasons: string[]
          }
    > {
        const reasons: string[] = []

        try {
            // Verify message digest if signed attributes are present (before signature check)
            if (this.signedAttrs) {
                const messageDigestAttr = this.signedAttrs.find(
                    (attr) => attr.type.value === OIDs.PKCS9.MESSAGE_DIGEST,
                )

                if (!messageDigestAttr) {
                    reasons.push(
                        'Signed attributes present but message digest attribute is missing',
                    )
                    return { valid: false, reasons }
                }

                if (messageDigestAttr.values.length === 0) {
                    reasons.push('Message digest attribute has no values')
                    return { valid: false, reasons }
                }

                // Get the message digest from the attribute
                const messageDigestOctetString =
                    messageDigestAttr.values[0].parseAs<OctetString>(
                        OctetString,
                    )
                const expectedDigest = messageDigestOctetString.bytes

                // Compute the actual digest of the content
                const actualDigest = await this.digestAlgorithm.digest(
                    options.data,
                )

                // Compare the digests
                if (
                    expectedDigest.length !== actualDigest.length ||
                    !expectedDigest.every(
                        (byte: number, index: number) =>
                            byte === actualDigest[index],
                    )
                ) {
                    reasons.push(
                        'Message digest in signed attributes does not match computed digest of content',
                    )
                    return { valid: false, reasons }
                }
            }

            const valid = await this.getVerificationAlgorithm().verify(
                this.getSignatureData(options.data),
                this.signature,
                options.publicKeyInfo,
            )

            if (valid) {
                return { valid: true }
            }

            reasons.push(
                `${this.sid.toHumanString()}: Signature verification failed`,
            )
        } catch (error) {
            if (error instanceof Error) {
                reasons.push(
                    `${this.sid.toHumanString()}: Verification failed: ${error.message}`,
                )
            } else {
                reasons.push(
                    `${this.sid.toHumanString()}: Verification failed: ${String(error)}`,
                )
            }
        }

        return { valid: false, reasons }
    }
}
