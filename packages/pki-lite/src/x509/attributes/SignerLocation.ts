import {
    Asn1Node,
    der,
    PkiBase,
    PkiSequence,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
import { DirectoryString } from '../DirectoryString.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a postal address.
 *
 * @asn
 * ```asn
 * PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
 * ```
 */
export class PostalAddress extends PkiSequence<DirectoryString> {
    protected maxSize?: number = 6

    static fromAsn1(asn1: Asn1Node): PostalAddress {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                "Object's schema was not verified against input data for PostalAddress",
            )
        }
        const value: DirectoryString[] = []

        for (const element of asn1.children) {
            value.push(DirectoryString.fromAsn1(element))
        }

        return new PostalAddress(...value)
    }
}

/**
 * SignerLocation Attribute
 *
 * @asn
 * ```asn
 * SignerLocation ::= SEQUENCE {
 *       -- at least one of the following must be present
 *      countryName          [0] DirectoryString      OPTIONAL,
 *                            -- as used to name a Country in X.500
 *      localityName         [1] DirectoryString      OPTIONAL,
 *                            -- as used to name a locality in X.500
 *      postalAdddress       [2] PostalAddress        OPTIONAL
 * }
 * ```
 */
export class SignerLocation extends PkiBase<SignerLocation> {
    countryName?: DirectoryString
    localityName?: DirectoryString
    postalAddress?: PostalAddress

    constructor(options?: {
        countryName?: DirectoryString
        localityName?: DirectoryString
        postalAddress?: DirectoryString[]
    }) {
        super()
        this.countryName = options?.countryName
        this.localityName = options?.localityName
        this.postalAddress = options?.postalAddress?.length
            ? new PostalAddress(...options.postalAddress)
            : undefined
    }

    static create(options: {
        countryName?: string
        localityName?: string
        postalAddress?: string[] | string
    }): SignerLocation {
        const postalAddress = Array.isArray(options.postalAddress)
            ? options.postalAddress
            : options.postalAddress
              ? [options.postalAddress]
              : undefined
        return new SignerLocation({
            countryName: options.countryName
                ? new DirectoryString.utf8String({ value: options.countryName })
                : undefined,
            localityName: options.localityName
                ? new DirectoryString.utf8String({
                      value: options.localityName,
                  })
                : undefined,
            postalAddress: postalAddress?.map(
                (line) => new DirectoryString.utf8String({ value: line }),
            ),
        })
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        if (this.countryName) {
            const asn1 = this.countryName.toAsn1()
            values.push(der.constructed(0, [asn1]))
        }

        if (this.localityName) {
            const asn1 = this.localityName.toAsn1()
            values.push(der.constructed(1, [asn1]))
        }

        if (this.postalAddress) {
            const asn1 = this.postalAddress.toAsn1()
            values.push(der.constructed(2, [asn1]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): SignerLocation {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Expected ASN.1 Sequence for SignerLocation',
            )
        }
        const value: SignerLocation = new SignerLocation()

        // The fields are EXPLICIT [n]: each wraps the value it tags
        for (const element of asn1.children) {
            if (
                element.tagClass !== TagClass.Context ||
                !element.constructed ||
                element.children.length !== 1
            ) {
                continue
            }
            const inner = element.children[0]
            switch (element.tag) {
                case 0:
                    value.countryName = DirectoryString.fromAsn1(inner)
                    break
                case 1:
                    value.localityName = DirectoryString.fromAsn1(inner)
                    break
                case 2:
                    value.postalAddress = PostalAddress.fromAsn1(inner)
                    break
            }
        }

        return value
    }
}
