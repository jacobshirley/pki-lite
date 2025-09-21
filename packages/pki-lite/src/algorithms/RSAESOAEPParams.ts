import { Asn1BaseBlock, asn1js, PkiBase, Asn1Any } from '../core/PkiBase.js'
import { AlgorithmIdentifier, PSourceAlgorithm } from './AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { OIDs } from '../core/OIDs.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * RSAES-OAEP-params ::= SEQUENCE {
 *   hashAlgorithm     [0] HashAlgorithm     DEFAULT sha1,
 *   maskGenAlgorithm  [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
 *   pSourceAlgorithm  [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty
 * }
 *
 * HashAlgorithm ::= AlgorithmIdentifier
 *
 * MaskGenAlgorithm ::= AlgorithmIdentifier
 *
 * PSourceAlgorithm ::= AlgorithmIdentifier
 *
 * Implementation based on RFC 3447 (PKCS #1 v2.1)
 */

export class RSAESOAEPParams extends PkiBase<RSAESOAEPParams> {
    hashAlgorithm?: AlgorithmIdentifier
    maskGenAlgorithm?: AlgorithmIdentifier
    pSourceAlgorithm?: PSourceAlgorithm

    /**
     * Default values as specified in RFC 3447
     */
    static defaultHashAlgorithm() {
        return AlgorithmIdentifier.digestAlgorithm('SHA-1')
    }

    static defaultMaskGenAlgorithm() {
        return new AlgorithmIdentifier({
            algorithm: OIDs.RSA.MGF1,
            parameters: RSAESOAEPParams.defaultHashAlgorithm().toAsn1(),
        })
    }

    static defaultPSourceAlgorithm() {
        return new AlgorithmIdentifier({
            algorithm: OIDs.RSA.PSPECIFIED,
            parameters: new OctetString({ bytes: new Uint8Array(0) }), // empty string
        })
    }

    /**
     * Creates a new instance of RSAESOAEPParams
     *
     * @param options Configuration options for RSA OAEP parameters
     * @param options.hashAlgorithm Hash algorithm to use (defaults to SHA-1)
     * @param options.maskGenAlgorithm Mask generation algorithm to use (defaults to MGF1 with SHA-1)
     * @param options.pSourceAlgorithm Source algorithm for encoding parameters (defaults to pSpecified with empty string)
     */
    constructor(
        options: {
            hashAlgorithm?: AlgorithmIdentifier
            maskGenAlgorithm?: AlgorithmIdentifier
            pSourceAlgorithm?: AlgorithmIdentifier
        } = {},
    ) {
        super()
        this.hashAlgorithm = options.hashAlgorithm
        this.maskGenAlgorithm = options.maskGenAlgorithm
        this.pSourceAlgorithm = options.pSourceAlgorithm
            ? new PSourceAlgorithm({
                  parameters: options.pSourceAlgorithm.parameters,
              })
            : undefined
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

        if (this.pSourceAlgorithm) {
            sequenceValue.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 2,
                    },
                    value: [this.pSourceAlgorithm.toAsn1()],
                }),
            )
        }

        sequence.valueBlock.value = sequenceValue
        return sequence
    }

    /**
     * Parse from ASN.1 structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): RSAESOAEPParams {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const params = new RSAESOAEPParams()

        // Extract tagged optional values
        for (const element of (asn1 as any).valueBlock.value) {
            if (element instanceof asn1js.Constructed) {
                const tagNumber = element.idBlock.tagNumber
                const value = element.valueBlock.value[0]

                switch (tagNumber) {
                    case 0: // hashAlgorithm [0]
                        params.hashAlgorithm =
                            AlgorithmIdentifier.fromAsn1(value)
                        break
                    case 1: // maskGenAlgorithm [1]
                        params.maskGenAlgorithm =
                            AlgorithmIdentifier.fromAsn1(value)
                        break
                    case 2: // pSourceAlgorithm [2]
                        params.pSourceAlgorithm =
                            PSourceAlgorithm.fromAsn1(value)
                        break
                }
            }
        }

        return params
    }

    /**
     * Get effective hash algorithm (either specified or default)
     */
    getEffectiveHashAlgorithm(): AlgorithmIdentifier {
        return this.hashAlgorithm || RSAESOAEPParams.defaultHashAlgorithm()
    }

    /**
     * Get effective mask generation algorithm (either specified or default)
     */
    getEffectiveMaskGenAlgorithm(): AlgorithmIdentifier {
        return (
            this.maskGenAlgorithm || RSAESOAEPParams.defaultMaskGenAlgorithm()
        )
    }

    /**
     * Get effective P source algorithm (either specified or default)
     */
    getEffectivePSourceAlgorithm(): AlgorithmIdentifier {
        return (
            this.pSourceAlgorithm || RSAESOAEPParams.defaultPSourceAlgorithm()
        )
    }

    /**
     * Creates a default instance with all parameters set to their defaults
     */
    static createDefault(): RSAESOAEPParams {
        return new RSAESOAEPParams()
    }
}
