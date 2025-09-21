import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
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
    toAsn1(): Asn1BaseBlock {
        const sequence = new asn1js.Sequence()
        const sequenceValue: asn1js.AsnType[] = []

        // Only include non-default values in the encoding
        if (this.hashAlgorithm) {
            sequenceValue.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0,
                    },
                    value: [this.hashAlgorithm.toAsn1()],
                }),
            )
        }

        if (this.maskGenAlgorithm) {
            sequenceValue.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1,
                    },
                    value: [this.maskGenAlgorithm.toAsn1()],
                }),
            )
        }

        if (this.saltLength !== undefined) {
            sequenceValue.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 2,
                    },
                    value: [new asn1js.Integer({ value: this.saltLength })],
                }),
            )
        }

        if (this.trailerField !== undefined) {
            sequenceValue.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 3,
                    },
                    value: [new asn1js.Integer({ value: this.trailerField })],
                }),
            )
        }

        sequence.valueBlock.value = sequenceValue
        return sequence
    }

    /**
     * Parse from ASN.1 structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): RSASSAPSSParams {
        if (!(asn1 instanceof asn1js.Sequence)) {
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
        for (const element of (asn1 as any).valueBlock.value) {
            if (element instanceof asn1js.Constructed) {
                const tagNumber = element.idBlock.tagNumber
                const value = element.valueBlock.value[0]

                switch (tagNumber) {
                    case 0: // hashAlgorithm [0]
                        options.hashAlgorithm =
                            AlgorithmIdentifier.fromAsn1(value)
                        break
                    case 1: // maskGenAlgorithm [1]
                        options.maskGenAlgorithm =
                            AlgorithmIdentifier.fromAsn1(value)
                        break
                    case 2: // saltLength [2]
                        if (value instanceof asn1js.Integer) {
                            options.saltLength = value.valueBlock.valueDec
                        }
                        break
                    case 3: // trailerField [3]
                        if (value instanceof asn1js.Integer) {
                            options.trailerField = value.valueBlock.valueDec
                        }
                        break
                }
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
