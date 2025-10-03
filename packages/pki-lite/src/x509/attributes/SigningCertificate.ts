import {
    Asn1Any,
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    PkiSequence,
} from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { IssuerAndSerialNumber } from '../../pkcs7/IssuerAndSerialNumber.js'
import { Any } from '../../asn1/Any.js'
import { PolicyInformation } from '../PolicyInformation.js'
import { Certificate } from '../Certificate.js'
import { IssuerSerial } from '../IssuerSerial.js'
import { GeneralName, GeneralNames } from '../GeneralName.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the ESSCertID structure described in RFC 5035.
 *
 * @asn
 * ```asn
 * ESSCertID ::= SEQUENCE {
 *      certHash          OCTET STRING,
 *      issuerSerial      IssuerSerial OPTIONAL
 * }
 *
 * Hash ::= OCTET STRING
 * ```
 */
export class ESSCertID extends PkiBase<ESSCertID> {
    certHash: OctetString
    issuerSerial?: IssuerSerial

    constructor(options: {
        certHash: Uint8Array<ArrayBuffer> | OctetString
        issuerSerial?: IssuerSerial
    }) {
        super()
        this.certHash = new OctetString({ bytes: options.certHash })
        this.issuerSerial = options.issuerSerial
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []
        values.push(this.certHash.toAsn1())

        if (this.issuerSerial) {
            values.push(this.issuerSerial.toAsn1())
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): ESSCertID {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                'Invalid ESSCertID: expected 1 to 2 elements',
            )
        }

        let certHash: OctetString
        let issuerSerial: IssuerSerial | undefined

        let index = 0
        // The first element must be the certHash
        if (!(values[index] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ESSCertID: expected OCTET STRING for certHash',
            )
        }
        certHash = OctetString.fromAsn1(values[index])
        index++

        // If there's another element, it must be the issuerSerial
        if (index < values.length) {
            issuerSerial = IssuerSerial.fromAsn1(values[index])
        }

        return new ESSCertID({
            certHash,
            issuerSerial,
        })
    }
}

/**
 * Represents the SigningCertificate structure described in RFC 5035.
 *
 * @asn
 * ```asn
 * SigningCertificate ::= SEQUENCE {
 *      certs        SEQUENCE OF ESSCertID,
 *      policies     SEQUENCE OF PolicyInformation OPTIONAL
 * }
 */
export class SigningCertificate extends PkiBase<SigningCertificate> {
    certs: ESSCertID[]
    policies?: PolicyInformation[]

    constructor(options: {
        certs: ESSCertID[]
        policies?: PolicyInformation[]
    }) {
        super()
        this.certs = options.certs
        this.policies = options.policies
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Sequence({
                value: this.certs.map((cert) => cert.toAsn1()),
            }),
        ]

        if (this.policies) {
            values.push(
                new asn1js.Sequence({
                    value: this.policies.map((policy) => policy.toAsn1()),
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): SigningCertificate {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                'Invalid SigningCertificate: expected 1 to 2 elements',
            )
        }

        const certsAsn1 = values[0]
        if (!(certsAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid SigningCertificate: expected SEQUENCE for certs',
            )
        }

        const certs = certsAsn1.valueBlock.value.map((c) =>
            ESSCertID.fromAsn1(c),
        )

        let policies: PolicyInformation[] | undefined
        if (values.length > 1) {
            const policiesAsn1 = values[1]
            if (!(policiesAsn1 instanceof asn1js.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid SigningCertificate: expected SEQUENCE for policies',
                )
            }

            policies = policiesAsn1.valueBlock.value.map((p) =>
                PolicyInformation.fromAsn1(p),
            )
        }

        return new SigningCertificate({ certs, policies })
    }

    static async fromCertificates(options: {
        certificates: Certificate[]
        policies?: PolicyInformation[]
    }): Promise<SigningCertificate> {
        const essCerts = await Promise.all(
            options.certificates.map(
                async (cert) =>
                    new ESSCertID({
                        certHash: await cert.getHash('SHA-1'), // RFC 5035 specifies SHA-1
                        issuerSerial: new IssuerSerial({
                            issuer: new GeneralNames(
                                GeneralName.directoryName.fromName(
                                    cert.tbsCertificate.issuer,
                                ),
                            ),
                            serialNumber: cert.tbsCertificate.serialNumber,
                        }),
                    }),
            ),
        )

        return new SigningCertificate({
            certs: essCerts,
            policies: options.policies,
        })
    }
}
