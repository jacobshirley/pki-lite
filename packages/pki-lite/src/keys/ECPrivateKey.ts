import { getCryptoProvider } from '../core/crypto/provider.js'
import { NamedCurve } from '../core/crypto/types.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    derToAsn1,
    pemToDer,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an EC private key according to RFC 5915.
 *
 * ASN.1 Structure:
 * ```
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 * ```
 */
export class ECPrivateKey extends PkiBase<ECPrivateKey> {
    /**
     * The version of the EC private key structure (always 1)
     */
    version: number = 1

    /**
     * The private key value as an octet string
     */
    privateKey: Uint8Array

    /**
     * The named curve OID (if parameters are present)
     * Most commonly this is a string like '1.2.840.10045.3.1.7' for P-256
     */
    namedCurve?: string

    /**
     * The key component (if included)
     */
    publicKey?: Uint8Array

    /**
     * Creates a new ECPrivateKey
     *
     * @param privateKey The private key as a Uint8Array
     * @param namedCurve The named curve OID (optional)
     * @param publicKey The key (optional)
     */
    constructor(options: {
        privateKey: Uint8Array
        namedCurve?: string
        publicKey?: Uint8Array
    }) {
        super()
        const { privateKey, namedCurve, publicKey } = options
        this.privateKey = privateKey
        this.namedCurve = namedCurve
        this.publicKey = publicKey
    }

    /**
     * Converts the ECPrivateKey to an ASN.1 structure
     */
    toAsn1(): Asn1BaseBlock {
        const result: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            new asn1js.OctetString({ valueHex: this.privateKey }),
        ]

        // Add [0] parameters (namedCurve) if present
        if (this.namedCurve) {
            const namedCurveAsn1 = new asn1js.ObjectIdentifier({
                value: this.namedCurve,
            })
            result.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [namedCurveAsn1],
                }),
            )
        }

        // Add [1] publicKey if present
        if (this.publicKey) {
            result.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    value: [new asn1js.BitString({ valueHex: this.publicKey })],
                }),
            )
        }

        return new asn1js.Sequence({ value: result })
    }

    /**
     * Converts the ECPrivateKey to a DER-encoded byte array
     */
    toDer(): Uint8Array {
        const asn1 = this.toAsn1()
        return new Uint8Array(asn1.toBER(false))
    }

    /**
     * Converts the ECPrivateKey to a PEM-encoded string
     */
    toPem(): string {
        return super.toPem()
    }

    /**
     * Creates an ECPrivateKey from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns An ECPrivateKey object
     */
    static fromAsn1(asn1: Asn1BaseBlock): ECPrivateKey {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 2 || values.length > 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2-4 elements, got ${values.length}`,
            )
        }

        // Version (must be 1)
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: version must be INTEGER',
            )
        }
        const version = values[0].valueBlock.valueDec
        if (version !== 1) {
            throw new Asn1ParseError(
                `Invalid EC private key version: expected 1, got ${version}`,
            )
        }

        // Private key
        if (!(values[1] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: privateKey must be OCTET STRING',
            )
        }
        const privateKey = new Uint8Array(values[1].valueBlock.valueHexView)

        let namedCurve: string | undefined
        let publicKey: Uint8Array | undefined

        // Optional parameters and publicKey
        for (let i = 2; i < values.length; i++) {
            const value = values[i]

            if (!(value instanceof asn1js.Constructed)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: optional elements must be tagged',
                )
            }

            const tagNumber = value.idBlock.tagNumber

            if (tagNumber === 0) {
                // [0] parameters
                // Parse the named curve OID
                if (value.valueBlock.value.length !== 1) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: parameters must contain exactly one element',
                    )
                }

                const curveParam = value.valueBlock.value[0]
                if (!(curveParam instanceof asn1js.ObjectIdentifier)) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: namedCurve must be an OBJECT IDENTIFIER',
                    )
                }

                namedCurve = curveParam.valueBlock.toString()
            } else if (tagNumber === 1) {
                // [1] publicKey
                // Parse the key bit string
                if (value.valueBlock.value.length !== 1) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: publicKey must contain exactly one element',
                    )
                }

                const pubKeyParam = value.valueBlock.value[0]
                if (!(pubKeyParam instanceof asn1js.BitString)) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: publicKey must be a BIT STRING',
                    )
                }

                publicKey = new Uint8Array(pubKeyParam.valueBlock.valueHexView)
            } else {
                throw new Asn1ParseError(
                    `Invalid ASN.1 structure: unexpected tag number ${tagNumber}`,
                )
            }
        }

        return new ECPrivateKey({ privateKey, namedCurve, publicKey })
    }

    /**
     * Creates an ECPrivateKey from a DER-encoded byte array
     *
     * @param der The DER-encoded ECPrivateKey
     * @returns An ECPrivateKey object
     */
    static fromDer(der: Uint8Array): ECPrivateKey {
        const asn1 = derToAsn1(der)
        return ECPrivateKey.fromAsn1(asn1)
    }

    /**
     * Creates an ECPrivateKey from a PEM-encoded string
     *
     * @param pem The PEM-encoded ECPrivateKey
     * @returns An ECPrivateKey object
     */
    static fromPem(pem: string): ECPrivateKey {
        return ECPrivateKey.fromDer(pemToDer(pem, ['EC PRIVATE KEY']))
    }

    /**
     * Creates an ECPrivateKey for a specific named curve
     *
     * @param curve The named curve OID (e.g., EC_CURVES.SECP256R1)
     * @param privateKey The private key value
     * @param publicKey Optional key value
     * @returns An ECPrivateKey object
     */
    static forCurve(
        curve: string,
        privateKey: Uint8Array,
        publicKey?: Uint8Array,
    ): ECPrivateKey {
        return new ECPrivateKey({ privateKey, namedCurve: curve, publicKey })
    }
}
