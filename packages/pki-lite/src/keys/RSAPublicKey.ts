import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    derToAsn1,
    pemToDer,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an RSA key as defined in RFC 8017 (PKCS #1 v2.2).
 *
 * @asn
 * ```asn
 * RSAPublicKey ::= SEQUENCE {
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER   -- e
 * }
 * ```
 */
export class RSAPublicKey extends PkiBase<RSAPublicKey> {
    /** The modulus (n) */
    modulus: Uint8Array

    /** The exponent (e) */
    publicExponent: Uint8Array

    /**
     * Creates a new RSAPublicKey instance.
     */
    constructor(options: { modulus: Uint8Array; publicExponent: Uint8Array }) {
        super()

        const { modulus, publicExponent } = options

        this.modulus = modulus
        this.publicExponent = publicExponent
    }

    get pemHeader(): string {
        return 'RSA PUBLIC KEY'
    }

    /**
     * Converts the RSA key to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ valueHex: this.modulus }),
                new asn1js.Integer({ valueHex: this.publicExponent }),
            ],
        })
    }

    /**
     * Parses an ASN.1 structure to create an RSAPublicKey.
     *
     * @param asn1 The ASN.1 structure
     * @returns A new RSAPublicKey instance
     */
    static fromAsn1(asn1: Asn1BaseBlock): RSAPublicKey {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = (asn1 as any).valueBlock.value
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        // Modulus
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: modulus must be INTEGER',
            )
        }
        const modulusBlock = values[0].valueBlock as any
        const modulus = new Uint8Array(
            modulusBlock.valueHexView || modulusBlock.valueBeforeDecodeView,
        )

        // Public Exponent
        if (!(values[1] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: publicExponent must be INTEGER',
            )
        }
        const exponentBlock = values[1].valueBlock as any
        const publicExponent = new Uint8Array(
            exponentBlock.valueHexView || exponentBlock.valueBeforeDecodeView,
        )

        return new RSAPublicKey({
            modulus,
            publicExponent,
        })
    }

    /**
     * Parses DER encoded data to create an RSAPublicKey.
     *
     * @param der The DER encoded data
     * @returns A new RSAPublicKey instance
     */
    static fromDer(der: Uint8Array): RSAPublicKey {
        const asn1 = derToAsn1(der)
        return RSAPublicKey.fromAsn1(asn1)
    }

    /**
     * Parses PEM encoded data to create an RSAPublicKey.
     *
     * @param pem The PEM encoded data
     * @returns A new RSAPublicKey instance
     */
    static fromPem(pem: string): RSAPublicKey {
        return RSAPublicKey.fromDer(pemToDer(pem, 'RSA PUBLIC KEY'))
    }
}
