import {
    Asn1Node,
    der,
    PkiBase,
    PkiSequence,
    UniversalTag,
} from '../../core/PkiBase.js'
import { GeneralName } from '../GeneralName.js'
import { RDNSequence } from '../RDNSequence.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag, isContextTag } from '../../core/tagging.js'

/**
 * Represents a GeneralSubtree structure used in name constraints.
 *
 * A GeneralSubtree defines a subtree of names along with optional minimum
 * and maximum distances for matching purposes.
 *
 * @asn
 * ```asn
 * GeneralSubtree ::= SEQUENCE {
 *      base                    GeneralName,
 *      minimum         [0]     BaseDistance DEFAULT 0,
 *      maximum         [1]     BaseDistance OPTIONAL
 * }
 * ```
 */
export class GeneralSubtree extends PkiBase<GeneralSubtree> {
    base: GeneralName
    minimum: number
    maximum?: number

    constructor(options: {
        base: GeneralName
        minimum?: number
        maximum?: number
    }) {
        super()

        const { base, minimum = 0, maximum } = options

        this.base = base
        this.minimum = minimum
        this.maximum = maximum
    }

    /**
     * Converts the GeneralSubtree to an ASN.1 structure.
     */
    toAsn1() {
        const values = []

        values.push(this.base.toAsn1())

        // minimum [0] and maximum [1] are IMPLICIT INTEGERs; minimum is DEFAULT 0, so
        // DER omits it when it is 0.
        if (this.minimum !== 0) {
            values.push(implicitTag(der.integer(this.minimum), 0))
        }

        if (this.maximum !== undefined) {
            values.push(implicitTag(der.integer(this.maximum), 1))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): GeneralSubtree {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for GeneralSubtree',
            )
        }

        const [baseAsn1, ...rest] = asn1.children
        if (!baseAsn1) {
            throw new Asn1ParseError(
                'Invalid GeneralSubtree: missing base GeneralName',
            )
        }

        // minimum [0] and maximum [1] are IMPLICIT INTEGERs
        const distance = (element: Asn1Node): number => {
            const integer = element.is(UniversalTag.Integer)
                ? element
                : element.retag(UniversalTag.Integer)
            return der.readNumber(integer)
        }

        let minimum: number | undefined
        let maximum: number | undefined
        for (const element of rest) {
            if (isContextTag(element, 0)) {
                minimum = distance(element)
            } else if (isContextTag(element, 1)) {
                maximum = distance(element)
            } else {
                throw new Asn1ParseError(
                    'Invalid GeneralSubtree: unexpected element',
                )
            }
        }

        return new GeneralSubtree({
            base: GeneralName.fromAsn1(baseAsn1),
            minimum,
            maximum,
        })
    }

    matches(
        other: GeneralName | string | RDNSequence | { toString: () => string },
    ): boolean {
        if (other instanceof RDNSequence) {
            other = other.toHumanString()
        }

        if (
            typeof other !== 'string' &&
            this.base.constructor !== other.constructor
        ) {
            return false
        }

        if (this.base instanceof GeneralName.rfc822Name) {
            const thisDomain = this.base.toString().split('@')[1]
            const otherDomain = other.toString().split('@')[1]
            return (
                thisDomain === otherDomain ||
                thisDomain.endsWith(`.${otherDomain}`)
            )
        }

        if (this.base instanceof GeneralName.dNSName) {
            return (
                this.base.toString() === other.toString() ||
                other.toString().endsWith(`.${this.base.toString()}`)
            )
        }

        if (this.base instanceof GeneralName.directoryName) {
            return this.base.toString() === other.toString()
        }

        if (this.base instanceof GeneralName.uniformResourceIdentifier) {
            return (
                this.base.toString() === other.toString() ||
                this.base.toString().startsWith(other.toString())
            )
        }

        // Other GeneralName types would require more complex logic
        // For now, we will return false for unsupported types
        return false
    }
}

/**
 * Represents a sequence of GeneralSubtree structures.
 *
 * This class extends PkiSequence and provides methods for matching
 * names against multiple subtrees.
 *
 * @asn
 * ```asn
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 * ```
 */
export class GeneralSubtrees extends PkiSequence<GeneralSubtree> {
    matches(other: GeneralName | string | RDNSequence): boolean {
        for (const subtree of this) {
            if (subtree.matches(other)) {
                return true
            }
        }
        return false
    }
}

/**
 * Represents the NameConstraints extension defined in RFC 5280.
 *
 * Name constraints provide a mechanism to restrict the set of names that
 * can appear in subsequent certificates in a certification path. This is
 * useful for limiting the scope of a CA's authority.
 *
 * @asn
 * ```asn
 * NameConstraints ::= SEQUENCE {
 *      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
 *      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL
 * }
 * ```
 */
export class NameConstraints extends PkiBase<NameConstraints> {
    /** Permitted subtrees */
    permittedSubtrees?: GeneralSubtrees
    /** Excluded subtrees */
    excludedSubtrees?: GeneralSubtrees

    constructor(options: {
        permittedSubtrees?: GeneralSubtree[]
        excludedSubtrees?: GeneralSubtree[]
    }) {
        super()
        const { permittedSubtrees, excludedSubtrees } = options
        this.permittedSubtrees = permittedSubtrees
            ? new GeneralSubtrees(...permittedSubtrees)
            : undefined
        this.excludedSubtrees = excludedSubtrees
            ? new GeneralSubtrees(...excludedSubtrees)
            : undefined
    }

    /**
     * Converts the NameConstraints to an ASN.1 structure.
     *
     * permittedSubtrees [0] and excludedSubtrees [1] are IMPLICIT GeneralSubtrees, so
     * the GeneralSubtree elements sit directly inside the tag (no SEQUENCE around them).
     */
    toAsn1() {
        const values = []

        if (this.permittedSubtrees) {
            values.push(
                der.constructed(
                    0,
                    this.permittedSubtrees.map((subtree) => subtree.toAsn1()),
                ),
            )
        }

        if (this.excludedSubtrees) {
            values.push(
                der.constructed(
                    1,
                    this.excludedSubtrees.map((subtree) => subtree.toAsn1()),
                ),
            )
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): NameConstraints {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for NameConstraints',
            )
        }

        const subtrees = (element: Asn1Node): GeneralSubtree[] => {
            if (!element?.constructed) {
                throw new Asn1ParseError(
                    'Invalid NameConstraints: subtrees must be constructed',
                )
            }
            let children = element.children
            // Earlier versions wrapped the subtrees in an extra SEQUENCE: [n] { SEQUENCE
            // { GeneralSubtree... } }. A GeneralSubtree's base is context-tagged, a
            // wrapped one starts with a SEQUENCE instead.
            const [first] = children
            if (
                children.length === 1 &&
                first.is(UniversalTag.Sequence) &&
                first.children[0]?.is(UniversalTag.Sequence)
            ) {
                children = first.children
            }
            return children.map((child) => GeneralSubtree.fromAsn1(child))
        }

        let permittedSubtrees: GeneralSubtree[] | undefined
        let excludedSubtrees: GeneralSubtree[] | undefined
        for (const element of asn1.children) {
            if (isContextTag(element, 0)) {
                permittedSubtrees = subtrees(element)
            } else if (isContextTag(element, 1)) {
                excludedSubtrees = subtrees(element)
            } else {
                throw new Asn1ParseError(
                    'Invalid NameConstraints: unexpected element',
                )
            }
        }

        return new NameConstraints({ permittedSubtrees, excludedSubtrees })
    }
}
