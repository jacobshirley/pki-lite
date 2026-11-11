import {
    Asn1Node,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { AlgorithmIdentifier } from './AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * RSASSA-PSS-params ::= SEQUENCE {
 *   hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
 *   saltLength         [2] INTEGER            DEFAULT 20,
 *   trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 * }
 *
 * HashAlgorithm ::= AlgorithmIdentifier
 *
 * MaskGenAlgorithm ::= AlgorithmIdentifier
 *
 * TrailerField ::= INTEGER { trailerFieldBC(1) }
 *
 * Implementation based on RFC 3447 (PKCS #1 v2.1)
 */
export class RSASSAPSSParams extends PkiBase<RSASSAPSSParams> {
    hashAlgorithm?: AlgorithmIdentifier
    maskGenAlgorithm?: AlgorithmIdentifier
    saltLength?: number
    trailerField?: number

    /**
     * Creates a new instance of RSASSAPSSParams
     */
    constructor(
        options: {
            hashAlgorithm?: AlgorithmIdentifier
            maskGenAlgorithm?: AlgorithmIdentifier
            saltLength?: number
            trailerField?: number
        } = {},
    ) {
        super()
        const { hashAlgorithm, maskGenAlgorithm, saltLength, trailerField } =
            options

        this.hashAlgorithm = hashAlgorithm
        this.maskGenAlgorithm = maskGenAlgorithm
        this.saltLength = saltLength
        this.trailerField = trailerField
    }

    /**
     * Converts to ASN.1 structure
     */
    toAsn1(): Asn1Node {
        // Fields are EXPLICIT [n]; only non-default values are present
        return der.sequence([
            this.hashAlgorithm?.toAsn1().explicit(0),
            this.maskGenAlgorithm?.toAsn1().explicit(1),
            this.saltLength === undefined
                ? undefined
                : der.integer(this.saltLength).explicit(2),
            this.trailerField === undefined
                ? undefined
                : der.integer(this.trailerField).explicit(3),
        ])
    }

    /**
     * Parse from ASN.1 structure
     */
    static fromAsn1(asn1: Asn1Node): RSASSAPSSParams {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const options: {
            hashAlgorithm?: AlgorithmIdentifier
            maskGenAlgorithm?: AlgorithmIdentifier
            saltLength?: number
            trailerField?: number
        } = {}

        // Extract tagged optional values
        for (const element of asn1.children) {
            if (
                element.tagClass !== TagClass.Context ||
                !element.constructed ||
                element.children.length === 0
            ) {
                continue
            }
            const value = element.children[0]

            switch (element.tag) {
                case 0: // hashAlgorithm [0]
                    options.hashAlgorithm = AlgorithmIdentifier.fromAsn1(value)
                    break
                case 1: // maskGenAlgorithm [1]
                    options.maskGenAlgorithm =
                        AlgorithmIdentifier.fromAsn1(value)
                    break
                case 2: // saltLength [2]
                    if (value.is(UniversalTag.Integer)) {
                        options.saltLength = der.readNumber(value)
                    }
                    break
                case 3: // trailerField [3]
                    if (value.is(UniversalTag.Integer)) {
                        options.trailerField = der.readNumber(value)
                    }
                    break
            }
        }

        return new RSASSAPSSParams(options)
    }

    static defaultHashAlgorithm() {
        return AlgorithmIdentifier.digestAlgorithm('SHA-1')
    }

    static defaultMaskGenAlgorithm() {
        return new AlgorithmIdentifier({
            algorithm: OIDs.RSA.MGF1,
            parameters: RSASSAPSSParams.defaultHashAlgorithm().toAsn1(),
        })
    }

    static defaultSaltLength() {
        return 20 // SHA-1 hash length in bytes
    }

    static defaultTrailerField() {
        return 1 // trailerFieldBC
    }

    /**
     * Get effective hash algorithm (either specified or default)
     */
    getEffectiveHashAlgorithm(): AlgorithmIdentifier {
        return this.hashAlgorithm || RSASSAPSSParams.defaultHashAlgorithm()
    }

    /**
     * Get effective mask generation algorithm (either specified or default)
     */
    getEffectiveMaskGenAlgorithm(): AlgorithmIdentifier {
        return (
            this.maskGenAlgorithm || RSASSAPSSParams.defaultMaskGenAlgorithm()
        )
    }

    /**
     * Get effective salt length (either specified or default)
     */
    getEffectiveSaltLength(): number {
        return this.saltLength !== undefined
            ? this.saltLength
            : RSASSAPSSParams.defaultSaltLength()
    }

    /**
     * Get effective trailer field (either specified or default)
     */
    getEffectiveTrailerField(): number {
        return this.trailerField !== undefined
            ? this.trailerField
            : RSASSAPSSParams.defaultTrailerField()
    }

    /**
     * Creates a default instance with all parameters set to their defaults
     */
    static createDefault(): RSASSAPSSParams {
        return new RSASSAPSSParams()
    }
}
