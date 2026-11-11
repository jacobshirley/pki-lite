import {
    Asn1Node,
    der,
    derToAsn1,
    pemToDer,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { Any } from '../asn1/Any.js'

/**
 * Represents an EC private key according to RFC 5915.
 *
 * Only named curves are interpreted. Explicit (`specifiedCurve`) or `implicitCurve`
 * parameters, which RFC 5480 deprecates, are kept as-is in {@link otherParameters} so the
 * key can still be read and written back unchanged.
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
    privateKey: Uint8Array<ArrayBuffer>

    /**
     * The named curve OID (if parameters are present)
     * Most commonly this is a string like '1.2.840.10045.3.1.7' for P-256
     */
    namedCurve?: string

    /**
     * The `parameters` value when it is not a named curve OID: an explicit
     * `SpecifiedECDomain` SEQUENCE or `implicitCurve NULL`. Not interpreted.
     */
    otherParameters?: Any

    /**
     * The key component (if included)
     */
    publicKey?: Uint8Array<ArrayBuffer>

    /**
     * Creates a new ECPrivateKey
     *
     * @param privateKey The private key as a Uint8Array<ArrayBuffer>
     * @param namedCurve The named curve OID (optional)
     * @param publicKey The key (optional)
     */
    constructor(options: {
        privateKey: Uint8Array<ArrayBuffer>
        namedCurve?: string
        otherParameters?: Any
        publicKey?: Uint8Array<ArrayBuffer>
    }) {
        super()
        const { privateKey, namedCurve, otherParameters, publicKey } = options
        this.privateKey = privateKey
        this.namedCurve = namedCurve
        this.otherParameters = otherParameters
        this.publicKey = publicKey
    }

    /**
     * Converts the ECPrivateKey to an ASN.1 structure
     */
    toAsn1(): Asn1Node {
        const result: Asn1Node[] = [
            der.integer(this.version),
            der.octetString(this.privateKey),
        ]

        // Add [0] parameters if present: a named curve OID, or kept-as-is other parameters
        const parameters = this.namedCurve
            ? der.oid(this.namedCurve)
            : this.otherParameters?.toAsn1()
        if (parameters) {
            result.push(parameters.explicit(0))
        }

        // Add [1] publicKey if present
        if (this.publicKey) {
            result.push(der.bitString(this.publicKey).explicit(1))
        }

        return der.sequence(result)
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
    static fromAsn1(asn1: Asn1Node): ECPrivateKey {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.children
        if (values.length < 2 || values.length > 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2-4 elements, got ${values.length}`,
            )
        }

        // Version (must be 1)
        if (!values[0].is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: version must be INTEGER',
            )
        }
        const version = der.readNumber(values[0])
        if (version !== 1) {
            throw new Asn1ParseError(
                `Invalid EC private key version: expected 1, got ${version}`,
            )
        }

        // Private key
        if (!values[1].is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: privateKey must be OCTET STRING',
            )
        }
        const privateKey = values[1].bytes()

        let namedCurve: string | undefined
        let otherParameters: Any | undefined
        let publicKey: Uint8Array<ArrayBuffer> | undefined

        // Optional parameters and publicKey
        for (let i = 2; i < values.length; i++) {
            const value = values[i]

            if (value.tagClass !== TagClass.Context || !value.constructed) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: optional elements must be tagged',
                )
            }

            const tagNumber = value.tag

            if (tagNumber === 0) {
                // [0] parameters
                // Parse the named curve OID
                if (value.children.length !== 1) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: parameters must contain exactly one element',
                    )
                }

                const curveParam = value.children[0]
                if (curveParam.is(UniversalTag.ObjectIdentifier)) {
                    namedCurve = der.readOid(curveParam)
                } else if (
                    curveParam.is(UniversalTag.Sequence) ||
                    curveParam.is(UniversalTag.Null)
                ) {
                    // specifiedCurve / implicitCurve: keep, but do not interpret
                    otherParameters = new Any({ derBytes: curveParam })
                } else {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: parameters must be an OBJECT IDENTIFIER (namedCurve), a SEQUENCE (specifiedCurve) or NULL (implicitCurve)',
                    )
                }
            } else if (tagNumber === 1) {
                // [1] publicKey
                // Parse the key bit string
                if (value.children.length !== 1) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: publicKey must contain exactly one element',
                    )
                }

                const pubKeyParam = value.children[0]
                if (!pubKeyParam.is(UniversalTag.BitString)) {
                    throw new Asn1ParseError(
                        'Invalid ASN.1 structure: publicKey must be a BIT STRING',
                    )
                }

                publicKey = der.readBitString(pubKeyParam).bytes
            } else {
                throw new Asn1ParseError(
                    `Invalid ASN.1 structure: unexpected tag number ${tagNumber}`,
                )
            }
        }

        return new ECPrivateKey({
            privateKey,
            namedCurve,
            otherParameters,
            publicKey,
        })
    }

    /**
     * Creates an ECPrivateKey from a DER-encoded byte array
     *
     * @param der The DER-encoded ECPrivateKey
     * @returns An ECPrivateKey object
     */
    static fromDer(der: Uint8Array<ArrayBuffer>): ECPrivateKey {
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
        privateKey: Uint8Array<ArrayBuffer>,
        publicKey?: Uint8Array<ArrayBuffer>,
    ): ECPrivateKey {
        return new ECPrivateKey({ privateKey, namedCurve: curve, publicKey })
    }

    get pemHeader(): string {
        return 'EC PRIVATE KEY'
    }
}
