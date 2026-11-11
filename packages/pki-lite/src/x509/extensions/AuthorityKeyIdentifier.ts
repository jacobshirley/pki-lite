import { Integer } from '../../asn1/Integer.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { KeyIdentifier } from '../../pkcs7/recipients/KeyIdentifier.js'
import { GeneralName, GeneralNames } from '../GeneralName.js'
import { contentOctets, implicitTag } from '../../core/tagging.js'

/**
 * AuthorityKeyIdentifier extension class.
 *
 * @asn
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
 * }
 */

export class AuthorityKeyIdentifier extends PkiBase<AuthorityKeyIdentifier> {
    keyIdentifier?: KeyIdentifier
    authorityCertIssuer?: GeneralNames
    authorityCertSerialNumber?: Integer

    constructor(params: {
        keyIdentifier?: KeyIdentifier
        authorityCertIssuer?: GeneralNames
        authorityCertSerialNumber?:
            | bigint
            | Integer
            | number
            | Uint8Array<ArrayBuffer>
    }) {
        super()
        this.keyIdentifier = params.keyIdentifier
        this.authorityCertIssuer = params.authorityCertIssuer
        this.authorityCertSerialNumber =
            params.authorityCertSerialNumber === undefined
                ? undefined
                : new Integer({ value: params.authorityCertSerialNumber })
    }

    /**
     * All three fields are IMPLICITly tagged: keyIdentifier and
     * authorityCertSerialNumber are primitive `[0]` / `[2]` values, and
     * authorityCertIssuer is a constructed `[1]` holding the GeneralName
     * elements directly.
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []
        if (this.keyIdentifier) {
            values.push(implicitTag(this.keyIdentifier.toAsn1(), 0))
        }
        if (this.authorityCertIssuer) {
            values.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 },
                    value: (
                        this.authorityCertIssuer.toAsn1() as asn1js.Sequence
                    ).valueBlock.value,
                }),
            )
        }
        if (this.authorityCertSerialNumber !== undefined) {
            values.push(implicitTag(this.authorityCertSerialNumber.toAsn1(), 2))
        }
        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): AuthorityKeyIdentifier {
        // All three fields are OPTIONAL, so an empty SEQUENCE is valid
        const sequence = asn1 as asn1js.Sequence

        let keyIdentifier: KeyIdentifier | undefined
        let authorityCertIssuer: GeneralNames | undefined
        let authorityCertSerialNumber: Integer | undefined

        for (const element of sequence.valueBlock.value) {
            const explicit =
                element instanceof asn1js.Constructed &&
                element.valueBlock.value.length === 1
                    ? element.valueBlock.value[0]
                    : undefined

            switch (element.idBlock.tagNumber) {
                case 0: // keyIdentifier [0] IMPLICIT OCTET STRING
                    if (explicit) {
                        // explicit form written by earlier versions
                        keyIdentifier = KeyIdentifier.fromAsn1(explicit)
                    } else if (element instanceof asn1js.OctetString) {
                        keyIdentifier = KeyIdentifier.fromAsn1(element)
                    } else {
                        keyIdentifier = new KeyIdentifier({
                            bytes: new Uint8Array(contentOctets(element)),
                        })
                    }
                    break
                case 1: // authorityCertIssuer [1] IMPLICIT GeneralNames
                    if (!(element instanceof asn1js.Constructed)) {
                        throw new Asn1ParseError(
                            'Invalid AuthorityKeyIdentifier: authorityCertIssuer must be constructed',
                        )
                    }
                    authorityCertIssuer =
                        explicit instanceof asn1js.Sequence
                            ? // explicit form written by earlier versions
                              GeneralNames.fromAsn1(explicit)
                            : new GeneralNames(
                                  ...element.valueBlock.value.map((name) =>
                                      GeneralName.fromAsn1(name),
                                  ),
                              )
                    break
                case 2: // authorityCertSerialNumber [2] IMPLICIT INTEGER
                    if (explicit) {
                        // explicit form written by earlier versions
                        authorityCertSerialNumber = Integer.fromAsn1(explicit)
                    } else if (element instanceof asn1js.Integer) {
                        authorityCertSerialNumber = Integer.fromAsn1(element)
                    } else {
                        authorityCertSerialNumber = new Integer({
                            value: new Uint8Array(contentOctets(element)),
                        })
                    }
                    break
                default:
                    throw new Asn1ParseError(
                        `Unexpected tag number ${element.idBlock.tagNumber} in AuthorityKeyIdentifier sequence`,
                    )
            }
        }

        return new AuthorityKeyIdentifier({
            keyIdentifier,
            authorityCertIssuer,
            authorityCertSerialNumber,
        })
    }
}
