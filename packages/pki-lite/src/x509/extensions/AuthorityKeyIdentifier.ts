import { Integer } from '../../asn1/Integer.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { KeyIdentifier } from '../../pkcs7/recipients/KeyIdentifier.js'
import { GeneralNames } from '../GeneralName.js'

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

    toAsn1(): Asn1BaseBlock {
        const sequence = new asn1js.Sequence({
            value: [],
        })
        if (this.keyIdentifier) {
            const keyIdBlock = new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // Context-specific
                    tagNumber: 0, // [0]
                },
                value: [this.keyIdentifier.toAsn1()],
            })
            sequence.valueBlock.value.push(keyIdBlock)
        }
        if (this.authorityCertIssuer) {
            const issuerBlock = new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // Context-specific
                    tagNumber: 1, // [1]
                },
                value: [this.authorityCertIssuer.toAsn1()],
            })
            sequence.valueBlock.value.push(issuerBlock)
        }
        if (this.authorityCertSerialNumber !== undefined) {
            const serialNumberBlock = new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // Context-specific
                    tagNumber: 2, // [2]
                },
                value: [this.authorityCertSerialNumber.toAsn1()],
            })
            sequence.valueBlock.value.push(serialNumberBlock)
        }
        return sequence
    }

    static fromAsn1(asn1: Asn1BaseBlock): AuthorityKeyIdentifier {
        const sequence = asn1 as asn1js.Sequence
        if (sequence.valueBlock.value.length === 0) {
            throw new Asn1ParseError(
                'AuthorityKeyIdentifier sequence has no elements',
            )
        }

        let keyIdentifier: KeyIdentifier | undefined
        let authorityCertIssuer: GeneralNames | undefined
        let authorityCertSerialNumber: Integer | undefined

        for (const element of sequence.valueBlock.value) {
            const tagNumber = element.idBlock.tagNumber
            console.log('sequence', asn1.toString(), tagNumber)

            switch (tagNumber) {
                case 0: // keyIdentifier [0] IMPLICIT OCTET STRING
                    if (element instanceof asn1js.Constructed) {
                        keyIdentifier = KeyIdentifier.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    } else {
                        keyIdentifier = KeyIdentifier.fromAsn1(element)
                    }
                    break
                case 1: // authorityCertIssuer
                    if (element instanceof asn1js.Constructed) {
                        authorityCertIssuer = GeneralNames.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    } else {
                        authorityCertIssuer = GeneralNames.fromAsn1(element)
                    }
                    break
                case 2: // authorityCertSerialNumber
                    if (element instanceof asn1js.Constructed) {
                        authorityCertSerialNumber = Integer.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    } else {
                        authorityCertSerialNumber = Integer.fromAsn1(element)
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
