import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { OIDs } from '../core/OIDs.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

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
        const values = [this.salt.toAsn1(), der.integer(this.iterationCount)]
        if (this.keyLength !== undefined) {
            values.push(der.integer(this.keyLength))
        }
        if (this.prf.parameters) {
            values.push(this.prf.toAsn1())
        }
        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): PBKDF2Params {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Error('PBKDF2: expected SEQUENCE')
        }
        const valueBlocks = asn1.children
        if (valueBlocks.length < 2) {
            throw new Error('PBKDF2: expected at least 2 elements in SEQUENCE')
        }

        let salt: OctetString | AlgorithmIdentifier
        const saltBlock = valueBlocks[0]
        if (saltBlock.is(UniversalTag.OctetString)) {
            salt = new OctetString({ bytes: saltBlock.bytes() })
        } else if (saltBlock.is(UniversalTag.Sequence)) {
            salt = AlgorithmIdentifier.fromAsn1(saltBlock)
        } else {
            throw new Error('PBKDF2: invalid salt type')
        }

        const iterationCountBlock = valueBlocks[1]
        if (!iterationCountBlock.is(UniversalTag.Integer)) {
            throw new Error('PBKDF2: iterationCount must be INTEGER')
        }
        const iterationCount = der.readNumber(iterationCountBlock)

        let keyLength: number | undefined
        let prf: AlgorithmIdentifier | undefined

        let index = 2

        if (valueBlocks[index]?.is(UniversalTag.Integer)) {
            keyLength = der.readNumber(valueBlocks[index])
            index++
        }

        if (valueBlocks[index]?.is(UniversalTag.Sequence)) {
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
