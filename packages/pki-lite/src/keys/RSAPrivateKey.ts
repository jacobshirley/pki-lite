import { getCryptoProvider } from '../core/crypto/crypto.js'
import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    pemToDer,
    PkiBase,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an RSA private key as defined in RFC 8017 (PKCS #1 v2.2).
 *
 * This class specifically implements the RSAPrivateKey ASN.1 structure from PKCS #1,
 * which differs from the generic PrivateKeyInfo structure defined in PKCS #8.
 *
 * Use this class when:
 * - Working directly with RSA-specific parameters (modulus, exponents, etc.)
 * - Parsing or creating traditional RSA private key formats
 * - Need access to the Chinese Remainder Theorem (CRT) parameters
 *
 * For general private key handling (including non-RSA keys), use PrivateKeyInfo instead.
 *
 * @asn
 * ```asn
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,  -- Integer, always 0 for two-prime, 1 for multi-prime
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 * ```
 */
export class RSAPrivateKey extends PkiBase<RSAPrivateKey> {
    /** The version (always 0 for two-prime RSA) */
    version: number

    /** The modulus (n) */
    modulus: Uint8Array

    /** The exponent (e) */
    publicExponent: Uint8Array

    /** The private exponent (d) */
    privateExponent: Uint8Array

    /** The first prime factor (p) */
    prime1: Uint8Array

    /** The second prime factor (q) */
    prime2: Uint8Array

    /** The first exponent (d mod (p-1)) */
    exponent1: Uint8Array

    /** The second exponent (d mod (q-1)) */
    exponent2: Uint8Array

    /** The CRT coefficient ((inverse of q) mod p) */
    coefficient: Uint8Array

    /**
     * Creates a new RSAPrivateKey instance.
     */
    constructor(options: {
        modulus: Uint8Array
        publicExponent: Uint8Array
        privateExponent: Uint8Array
        prime1: Uint8Array
        prime2: Uint8Array
        exponent1: Uint8Array
        exponent2: Uint8Array
        coefficient: Uint8Array
        version?: number
    }) {
        super()

        const {
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
            version = 0,
        } = options

        this.version = version
        this.modulus = modulus
        this.publicExponent = publicExponent
        this.privateExponent = privateExponent
        this.prime1 = prime1
        this.prime2 = prime2
        this.exponent1 = exponent1
        this.exponent2 = exponent2
        this.coefficient = coefficient
    }

    get pemHeader(): string {
        return 'PRIVATE KEY'
    }

    /**
     * Converts the RSA private key to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: this.version }),
                new asn1js.Integer({ valueHex: this.modulus }),
                new asn1js.Integer({ valueHex: this.publicExponent }),
                new asn1js.Integer({ valueHex: this.privateExponent }),
                new asn1js.Integer({ valueHex: this.prime1 }),
                new asn1js.Integer({ valueHex: this.prime2 }),
                new asn1js.Integer({ valueHex: this.exponent1 }),
                new asn1js.Integer({ valueHex: this.exponent2 }),
                new asn1js.Integer({ valueHex: this.coefficient }),
            ],
        })
    }

    /**
     * Converts the RSA private key to DER format.
     */
    toDer(): Uint8Array {
        const asn1 = this.toAsn1()
        return new Uint8Array(asn1.toBER(false))
    }

    /**
     * Extracts the RSA key component from this private key.
     *
     * @returns A new RSAPublicKey containing the parts of this key
     */
    toPublicKey(): any {
        // This requires importing RSAPublicKey, which would create a circular dependency
        // Instead, we'll return an object with the necessary components
        return {
            modulus: this.modulus,
            publicExponent: this.publicExponent,
        }
    }

    /**
     * Parses an ASN.1 structure to create an RSAPrivateKey.
     *
     * @param asn1 The ASN.1 structure
     * @returns A new RSAPrivateKey instance
     */
    static fromAsn1(asn1: Asn1BaseBlock): RSAPrivateKey {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = (asn1 as any).valueBlock.value
        if (values.length < 9) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 9 elements, got ${values.length}`,
            )
        }

        // Version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: version must be INTEGER',
            )
        }
        const version = values[0].valueBlock.valueDec

        // Check that all other elements are Integers
        const components: Uint8Array[] = []
        for (let i = 1; i < 9; i++) {
            if (!(values[i] instanceof asn1js.Integer)) {
                throw new Asn1ParseError(
                    `Invalid ASN.1 structure: element at index ${i} must be INTEGER`,
                )
            }
            // Access the value through valueBlock
            const integerBlock = values[i].valueBlock as any // Using any to bypass TypeScript checks
            components.push(
                new Uint8Array(
                    integerBlock.valueHexView ||
                        integerBlock.valueBeforeDecodeView,
                ),
            )
        }

        return new RSAPrivateKey({
            modulus: components[0],
            publicExponent: components[1],
            privateExponent: components[2],
            prime1: components[3],
            prime2: components[4],
            exponent1: components[5],
            exponent2: components[6],
            coefficient: components[7],
            version,
        })
    }

    /**
     * Parses DER encoded data to create an RSAPrivateKey.
     *
     * @param der The DER encoded data
     * @returns A new RSAPrivateKey instance
     */
    static fromDer(der: Uint8Array): RSAPrivateKey {
        const asn1 = derToAsn1(der)
        return RSAPrivateKey.fromAsn1(asn1)
    }

    /**
     * Parses PEM encoded data to create an RSAPrivateKey.
     *
     * @param pem The PEM encoded data
     * @returns A new RSAPrivateKey instance
     */
    static fromPem(pem: string): RSAPrivateKey {
        return RSAPrivateKey.fromDer(pemToDer(pem, 'PRIVATE KEY'))
    }
}
