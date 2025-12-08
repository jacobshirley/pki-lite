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
            // Check if element has context-specific tag class
            if (element.idBlock.tagClass !== 3) {
                throw new Asn1ParseError(
                    'Expected context-specific tag in AuthorityKeyIdentifier sequence',
                )
            }

            switch (element.idBlock.tagNumber) {
                case 0: // keyIdentifier [0] IMPLICIT OCTET STRING
                    // For IMPLICIT tagging, the element itself is the OCTET STRING with [0] tag
                    if (element instanceof asn1js.Constructed) {
                        // EXPLICIT tagging: [0] { OCTET STRING }
                        keyIdentifier = KeyIdentifier.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    } else {
                        // IMPLICIT tagging: [0] (primitive OCTET STRING)
                        // Create KeyIdentifier directly from the primitive element's valueHex
                        keyIdentifier = new KeyIdentifier({
                            bytes: (element as asn1js.Primitive).valueBlock
                                .valueHexView,
                        })
                    }
                    break
                case 1: // authorityCertIssuer [1] IMPLICIT GeneralNames
                    if (element instanceof asn1js.Constructed) {
                        // GeneralNames is a SEQUENCE, so it's always constructed
                        authorityCertIssuer = GeneralNames.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    } else {
                        throw new Asn1ParseError(
                            'Expected constructed element for authorityCertIssuer',
                        )
                    }
                    break
                case 2: // authorityCertSerialNumber [2] IMPLICIT INTEGER
                    if (element instanceof asn1js.Constructed) {
                        // EXPLICIT tagging: [2] { INTEGER }
                        authorityCertSerialNumber = Integer.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    } else {
                        // IMPLICIT tagging: [2] (primitive INTEGER)
                        // Create Integer directly from the primitive element's valueHex
                        authorityCertSerialNumber = new Integer({
                            value: new Uint8Array(
                                (
                                    element as asn1js.Primitive
                                ).valueBlock.valueHexView,
                            ),
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
