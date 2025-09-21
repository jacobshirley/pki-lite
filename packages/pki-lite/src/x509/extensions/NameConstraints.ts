import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    PkiSequence,
} from '../../core/PkiBase.js'
import { GeneralName } from '../GeneralName.js'
import { RDNSequence } from '../RDNSequence.js'

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

        if (this.minimum !== 0) {
            values.push(
                new asn1js.Integer({
                    value: this.minimum,
                    optional: true,
                    idBlock: { tagClass: 3, tagNumber: 0 }, // [0]
                }),
            )
        }

        if (this.maximum !== undefined) {
            values.push(
                new asn1js.Integer({
                    value: this.maximum,
                    optional: true,
                    idBlock: { tagClass: 3, tagNumber: 1 }, // [1]
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
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
     */
    toAsn1() {
        const values = []

        if (this.permittedSubtrees) {
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 }, // [0]
                    value: [this.permittedSubtrees.toAsn1()],
                }),
            )
        }

        if (this.excludedSubtrees) {
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 }, // [1]
                    value: [this.excludedSubtrees.toAsn1()],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }
}
