import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Attribute } from '../x509/Attribute.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    ObjectIdentifierString,
    derToAsn1,
    ParseableAsn1,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OIDs } from '../core/OIDs.js'

/**
 * Represents a SafeBag structure in a PKCS#12 file.
 *
 * A SafeBag is a container for different types of objects stored in PKCS#12
 * files, such as certificates, private keys, and CRLs. Each bag has a specific
 * type (bagId) that determines how to interpret the bag's content (bagValue).
 * Optional attributes can provide additional metadata like friendly names.
 *
 * @asn
 * ```asn
 * SafeBag ::= SEQUENCE {
 *   bagId         BAG-TYPE,
 *   bagValue      [0] EXPLICIT ANY DEFINED BY bagId,
 *   bagAttributes SET OF PKCS12Attribute OPTIONAL
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Create a certificate bag
 * const certBag = new SafeBag({
 *     bagId: OIDs.certBag,
 *     bagValue: new CertBag({
 *         certId: OIDs.x509Certificate,
 *         certValue: certificate.toDer()
 *     }),
 *     bagAttributes: [
 *         new Attribute({
 *             type: OIDs.friendlyName,
 *             values: ['My Certificate']
 *         })
 *     ]
 * })
 *
 * // Create a private key bag
 * const keyBag = new SafeBag({
 *     bagId: OIDs.pkcs8ShroudedKeyBag,
 *     bagValue: encryptedPrivateKeyInfo
 * })
 *
 * // Extract content based on bag type
 * if (safeBag.bagId.is(OIDs.certBag)) {
 *     const certBag = CertBag.fromAsn1(safeBag.bagValue.toAsn1())
 *     const certificate = certBag.extractCertificate()
 * }
 * ```
 */
export class SafeBag extends PkiBase<SafeBag> {
    /**
     * Object identifier specifying the type of bag content.
     * Common types include certBag, pkcs8ShroudedKeyBag, and keyBag.
     */
    bagId: ObjectIdentifier

    /**
     * The bag content, format determined by the bagId.
     */
    bagValue: Any

    /**
     * Optional attributes providing metadata (e.g., friendly names, local key ID).
     */
    bagAttributes?: Attribute[]

    /**
     * Creates a new SafeBag instance.
     *
     * @param options Configuration object
     * @param options.bagId Object identifier specifying the bag type
     * @param options.bagValue The bag content data
     * @param options.bagAttributes Optional attributes for the bag
     */
    constructor(options: {
        bagId: ObjectIdentifierString
        bagValue: Asn1Any
        bagAttributes?: Attribute[]
    }) {
        super()
        this.bagId = new ObjectIdentifier({ value: options.bagId })
        this.bagValue = new Any({ derBytes: options.bagValue })
        this.bagAttributes = options.bagAttributes
    }

    /**
     * Converts this SafeBag to its ASN.1 representation.
     *
     * @returns The ASN.1 SEQUENCE structure
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            this.bagId.toAsn1(),
            new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 },
                value: [this.bagValue.toAsn1()],
            }),
        ]

        if (this.bagAttributes && this.bagAttributes.length > 0) {
            values.push(
                new asn1js.Set({
                    value: this.bagAttributes.map((a) => a.toAsn1()),
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): SafeBag {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'SafeBag: expected SEQUENCE but got ' + asn1.constructor.name,
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 2 || values.length > 3) {
            throw new Asn1ParseError('SafeBag: expected 2 or 3 elements')
        }
        const id = values[0]
        const bagVal = values[1]
        if (!(id instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError('SafeBag: bagId must be OBJECT IDENTIFIER')
        }
        if (
            !(bagVal instanceof asn1js.Constructed) ||
            bagVal.idBlock.tagClass !== 3 ||
            bagVal.idBlock.tagNumber !== 0 ||
            bagVal.valueBlock.value.length !== 1
        ) {
            throw new Asn1ParseError(
                'SafeBag: bagValue must be [0] EXPLICIT with single element',
            )
        }

        let attrs: Attribute[] | undefined
        if (values.length === 3) {
            const set = values[2]
            if (!(set instanceof asn1js.Set)) {
                throw new Asn1ParseError('SafeBag: bagAttributes must be SET')
            }
            attrs = set.valueBlock.value.map((x) => Attribute.fromAsn1(x))
        }

        return new SafeBag({
            bagId: id.valueBlock.toString(),
            bagValue: new Any({ derBytes: bagVal.valueBlock.value[0] }),
            bagAttributes: attrs,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): SafeBag {
        return SafeBag.fromAsn1(derToAsn1(der))
    }

    is(type: keyof typeof OIDs.PKCS12.BAGS): boolean {
        const oid = OIDs.PKCS12.BAGS[type]
        return this.bagId.is(oid)
    }

    isOid(oid: string): boolean {
        return this.bagId.is(oid)
    }

    getAs<T>(parseable: ParseableAsn1<T>): T {
        return this.bagValue.parseAs(parseable)
    }
}
