import {
    Asn1Node,
    der,
    derToAsn1,
    pemToDer,
    PkiBase,
    UniversalTag,
} from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Attribute } from '../x509/Attribute.js'
import { RSAPrivateKey } from './RSAPrivateKey.js'
import { ECPrivateKey } from './ECPrivateKey.js'
import { OIDs } from '../core/OIDs.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OctetString } from '../asn1/OctetString.js'

/**
 * Represents a private key in PKCS#8 format.
 *
 * PrivateKeyInfo is the standard format for encoding private keys as defined
 * in PKCS#8. It includes the algorithm identifier, the private key material,
 * and optional attributes. This format is algorithm-agnostic and can represent
 * RSA, ECDSA, EdDSA, and other types of private keys.
 *
 * @asn
 * ```asn
 * PrivateKeyInfo ::= SEQUENCE {
 *      version                 Version,
 *      privateKeyAlgorithm     AlgorithmIdentifier,
 *      privateKey              OCTET STRING,
 *      attributes          [0] IMPLICIT Attributes OPTIONAL
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Create a private key info structure
 * const privateKeyInfo = new PrivateKeyInfo({
 *     algorithm: new AlgorithmIdentifier({
 *         algorithm: OIDs.rsaEncryption
 *     }),
 *     privateKey: rsaPrivateKeyBytes
 * })
 *
 * // Load from PEM
 * const pem = '-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----'
 * const keyInfo = PrivateKeyInfo.fromPem(pem)
 *
 * // Extract the actual private key
 * const rsaKey = keyInfo.extractRSAPrivateKey()
 * ```
 */
export class PrivateKeyInfo extends PkiBase<PrivateKeyInfo> {
    /**
     * Version number (usually 0 for PKCS#8 v1).
     */
    version: number

    /**
     * Algorithm identifier specifying the private key algorithm and parameters.
     */
    algorithm: AlgorithmIdentifier

    /**
     * The private key material as an OCTET STRING.
     * The format of this data depends on the algorithm.
     */
    privateKey: OctetString

    /**
     * Optional attributes providing additional key metadata.
     */
    attributes?: Attribute[]

    /**
     * Creates a new PrivateKeyInfo instance.
     *
     * @param options Configuration object
     * @param options.algorithm The private key algorithm identifier
     * @param options.privateKey The private key bytes or OctetString
     * @param options.version Version number (defaults to 0)
     * @param options.attributes Optional key attributes
     */
    constructor(options: {
        algorithm: AlgorithmIdentifier
        privateKey: Uint8Array<ArrayBuffer> | OctetString
        version?: number
        attributes?: Attribute[]
    }) {
        super()

        const { algorithm, privateKey, version = 0, attributes } = options

        this.version = version
        this.algorithm = algorithm
        this.privateKey = new OctetString({ bytes: privateKey })
        this.attributes = attributes
    }

    /**
     * Converts this PrivateKeyInfo to its ASN.1 representation.
     *
     * @returns The ASN.1 SEQUENCE structure
     */
    toAsn1(): Asn1Node {
        const values = [
            der.integer(this.version),
            this.algorithm.toAsn1(),
            this.privateKey.toAsn1(),
        ]

        if (this.attributes) {
            // [0] IMPLICIT SET OF Attribute
            values.push(
                der.constructed(
                    0,
                    this.attributes.map((attr) => attr.toAsn1()),
                ),
            )
        }

        return der.sequence(values)
    }

    /**
     * Creates a PrivateKeyInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A PrivateKeyInfo
     */
    static fromAsn1(asn1: Asn1Node): PrivateKeyInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.children.length < 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 3 elements',
            )
        }

        const versionAsn1 = asn1.children[0]
        const algorithmAsn1 = asn1.children[1]
        const privateKeyAsn1 = asn1.children[2]

        if (!versionAsn1.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: version must be an INTEGER',
            )
        }

        if (!algorithmAsn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: algorithm must be a SEQUENCE',
            )
        }

        if (!privateKeyAsn1.is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: privateKey must be an OCTET STRING',
            )
        }

        const version = der.readNumber(versionAsn1)
        const algorithm = AlgorithmIdentifier.fromAsn1(algorithmAsn1)
        const privateKey = privateKeyAsn1.bytes()

        // Check for optional attributes [0] IMPLICIT
        let attributes: Attribute[] | undefined
        if (asn1.children.length > 3) {
            const attributesAsn1 = asn1.children[3]

            if (attributesAsn1.constructed && attributesAsn1.isContext(0)) {
                attributes = attributesAsn1.children.map((attrAsn1) =>
                    Attribute.fromAsn1(attrAsn1),
                )
            }
        }

        return new PrivateKeyInfo({
            algorithm,
            privateKey,
            version,
            attributes,
        })
    }

    static fromPem(pem: string): PrivateKeyInfo {
        const der = pemToDer(pem, ['PRIVATE KEY'])
        const asn1 = derToAsn1(der)
        return PrivateKeyInfo.fromAsn1(asn1)
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): PrivateKeyInfo {
        return PrivateKeyInfo.fromAsn1(derToAsn1(der))
    }

    getRsaPrivateKey(): RSAPrivateKey {
        return this.privateKey.parseAs(RSAPrivateKey)
    }

    getEcPrivateKey(): ECPrivateKey {
        return this.privateKey.parseAs(ECPrivateKey)
    }

    getPrivateKey(): RSAPrivateKey | ECPrivateKey {
        if (this.algorithm.algorithm.toString() === OIDs.RSA.ENCRYPTION) {
            return this.getRsaPrivateKey()
        } else {
            return this.getEcPrivateKey()
        }
    }

    get pemHeader(): string {
        return 'PRIVATE KEY'
    }
}
