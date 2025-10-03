import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { OIDs } from '../core/OIDs.js'
import { asn1js, PkiBase } from '../core/PkiBase.js'

/**
 * Represents PBKDF2-params structure.
 *
 * @asn
 * ```asn
 * PBKDF2-params ::= SEQUENCE {
 *   salt CHOICE {
 *     specified OCTET STRING,
 *     otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
 *   },
 *   iterationCount INTEGER (1..MAX),
 *   keyLength INTEGER (1..MAX) OPTIONAL,
 *   prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
 *     algid-hmacWithSHA1
 * }
 * ```
 */
export class PBKDF2Params extends PkiBase<PBKDF2Params> {
    salt: OctetString | AlgorithmIdentifier
    iterationCount: number
    keyLength?: number
    prf: DigestAlgorithmIdentifier = new DigestAlgorithmIdentifier({
        algorithm: OIDs.HASH.HMAC_SHA1,
    })

    constructor(options: {
        salt: Uint8Array<ArrayBuffer> | AlgorithmIdentifier | OctetString
        iterationCount: number
        keyLength?: number
        prf?: AlgorithmIdentifier
    }) {
        super()
        if (options.salt instanceof Uint8Array) {
            this.salt = new OctetString({ bytes: options.salt })
        } else {
            this.salt = options.salt
        }
        this.iterationCount = options.iterationCount
        this.keyLength = options.keyLength

        if (options.prf) {
            this.prf = new DigestAlgorithmIdentifier(options.prf)
        }
    }

    toAsn1() {
        const values = [
            this.salt.toAsn1(),
            new asn1js.Integer({ value: this.iterationCount }),
        ]
        if (this.keyLength !== undefined) {
            values.push(new asn1js.Integer({ value: this.keyLength }))
        }
        if (this.prf.parameters) {
            values.push(this.prf.toAsn1())
        }
        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: asn1js.BaseBlock): PBKDF2Params {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Error('PBKDF2: expected SEQUENCE')
        }
        const valueBlocks = asn1.valueBlock.value
        if (valueBlocks.length < 2) {
            throw new Error('PBKDF2: expected at least 2 elements in SEQUENCE')
        }

        let salt: OctetString | AlgorithmIdentifier
        const saltBlock = valueBlocks[0]
        if (saltBlock instanceof asn1js.OctetString) {
            salt = new OctetString({ bytes: saltBlock.valueBlock.valueHexView })
        } else if (saltBlock instanceof asn1js.Sequence) {
            salt = AlgorithmIdentifier.fromAsn1(saltBlock)
        } else {
            throw new Error('PBKDF2: invalid salt type')
        }

        const iterationCountBlock = valueBlocks[1]
        if (!(iterationCountBlock instanceof asn1js.Integer)) {
            throw new Error('PBKDF2: iterationCount must be INTEGER')
        }
        const iterationCount = iterationCountBlock.valueBlock.valueDec

        let keyLength: number | undefined
        let prf: AlgorithmIdentifier | undefined

        let index = 2

        if (valueBlocks[index] instanceof asn1js.Integer) {
            keyLength = (valueBlocks[index] as asn1js.Integer).valueBlock
                .valueDec
            index++
        }

        if (valueBlocks[index] instanceof asn1js.Sequence) {
            prf = AlgorithmIdentifier.fromAsn1(valueBlocks[index])
        }

        return new PBKDF2Params({
            salt,
            iterationCount,
            keyLength,
            prf,
        })
    }
}
