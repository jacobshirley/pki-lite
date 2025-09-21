import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    PkiBase,
    PkiSet,
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
    static fromAsn1(asn1: Asn1BaseBlock): UnsignedAttributes {
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
    static fromAsn1(asn1: Asn1BaseBlock): SignedAttributes {
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
    signature: Uint8Array
    unsignedAttrs?: UnsignedAttributes

    constructor(options: {
        version: CMSVersion
        sid: SignerIdentifier
        digestAlgorithm: AlgorithmIdentifier
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array
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

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
        ]

        const signerIdAsn1 = this.sid.toAsn1()
        // Add the SignerIdentifier (CHOICE)
        if (this.sid instanceof IssuerAndSerialNumber) {
            values.push(signerIdAsn1)
        } else {
            signerIdAsn1.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
            signerIdAsn1.idBlock.tagNumber = 0 // [0]
        }

        values.push(this.digestAlgorithm.toAsn1())

        // SignedAttrs [0] IMPLICIT (optional)
        if (this.signedAttrs && this.signedAttrs.length > 0) {
            const attributesAsn1 = this.signedAttrs.toAsn1()

            attributesAsn1.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
            attributesAsn1.idBlock.tagNumber = 0 // [0]
            attributesAsn1.idBlock.isConstructed = true

            values.push(attributesAsn1)
        }

        values.push(
            this.signatureAlgorithm.toAsn1(),
            new asn1js.OctetString({ valueHex: this.signature }),
        )

        // UnsignedAttrs [1] IMPLICIT (optional)
        if (this.unsignedAttrs && this.unsignedAttrs.length > 0) {
            const attributesAsn1 = this.unsignedAttrs.toAsn1()
            attributesAsn1.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
            attributesAsn1.idBlock.tagNumber = 1 // [1]
            attributesAsn1.idBlock.isConstructed = true

            values.push(attributesAsn1)
        }

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a SignerInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A SignerInfo object
     */
    static fromAsn1(asn1: Asn1BaseBlock): SignerInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 5) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 5 elements, got ${values.length}`,
            )
        }

        let index = 0

        // Version
        if (!(values[index] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = (values[index] as asn1js.Integer).valueBlock.valueDec
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
            values[index].idBlock.tagClass === 3 && // CONTEXT-SPECIFIC
            values[index].idBlock.tagNumber === 0 // [0]
        ) {
            signedAttrs = SignedAttributes.fromAsn1(values[index])
            index++
        }

        // SignatureAlgorithm
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[index])
        index++

        // Signature
        if (!(values[index] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for signature',
            )
        }
        const signature = new Uint8Array(
            (values[index] as asn1js.OctetString).valueBlock.valueHexView,
        )
        index++

        // UnsignedAttrs (optional)
        let unsignedAttrs: Attribute[] | undefined = undefined
        if (
            index < values.length &&
            values[index].idBlock.tagClass === 3 && // CONTEXT-SPECIFIC
            values[index].idBlock.tagNumber === 1 // [1]
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

    static fromDer(derBytes: Uint8Array): SignerInfo {
        return SignerInfo.fromAsn1(derToAsn1(derBytes))
    }

    private getSignatureData(data?: Uint8Array): Uint8Array {
        if (this.signedAttrs) {
            // When signed attributes are present, the signature is computed over the
            // DER encoding of the SignedAttributes value
            const asn1 = this.signedAttrs.toAsn1()
            return new Uint8Array(asn1.toBER(false))
        }

        if (data) {
            // When no signed attributes are present, the signature is computed over the data
            return data
        }

        throw new Error(
            'No signed attributes present and no data provided for signature verification',
        )
    }

    async verify(options: {
        data?: Uint8Array
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
            const valid = await this.signatureAlgorithm.verify(
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
