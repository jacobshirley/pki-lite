import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { PolicyInformation } from '../PolicyInformation.js'
import { Certificate } from '../Certificate.js'
import { OIDs } from '../../core/OIDs.js'
import { IssuerSerial } from '../IssuerSerial.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the ESSCertIDv2 structure described in RFC 5035.
 *
 * @asn
 * ```asn
 * ESSCertIDv2 ::= SEQUENCE {
 *      hashAlgorithm     AlgorithmIdentifier DEFAULT {algorithm id-sha256},
 *      certHash          OCTET STRING,
 *      issuerSerial      IssuerSerial OPTIONAL
 * }
 *
 * Hash ::= OCTET STRING
 * ```
 */
export class ESSCertIDv2 extends PkiBase<ESSCertIDv2> {
    hashAlgorithm?: AlgorithmIdentifier
    certHash: OctetString
    issuerSerial?: IssuerSerial

    constructor(options: {
        hashAlgorithm?: AlgorithmIdentifier
        certHash: Uint8Array | OctetString
        issuerSerial?: IssuerSerial
    }) {
        super()
        this.hashAlgorithm = options.hashAlgorithm
        this.certHash = new OctetString({ bytes: options.certHash })
        this.issuerSerial = options.issuerSerial
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []

        if (this.hashAlgorithm) {
            values.push(this.hashAlgorithm.toAsn1())
        }

        values.push(this.certHash.toAsn1())

        if (this.issuerSerial) {
            values.push(this.issuerSerial.toAsn1())
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): ESSCertIDv2 {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 3) {
            throw new Asn1ParseError(
                'Invalid ESSCertIDv2: expected 1 to 3 elements',
            )
        }

        let hashAlgorithm: AlgorithmIdentifier | undefined
        let certHash: OctetString
        let issuerSerial: IssuerSerial | undefined

        let index = 0

        // Check if the first element is an AlgorithmIdentifier
        if (values[index] instanceof asn1js.Sequence) {
            hashAlgorithm = AlgorithmIdentifier.fromAsn1(values[index])
            index++
        }

        // The next element must be the certHash
        if (!(values[index] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ESSCertIDv2: expected OCTET STRING for certHash',
            )
        }
        certHash = OctetString.fromAsn1(values[index])
        index++

        // If there's another element, it must be the issuerSerial
        if (index < values.length) {
            issuerSerial = IssuerSerial.fromAsn1(values[index])
        }

        return new ESSCertIDv2({
            hashAlgorithm,
            certHash,
            issuerSerial,
        })
    }
}

/**
 * Represents the SigningCertificateV2 structure described in RFC 5035.
 *
 * @asn
 * ```asn
 * SigningCertificateV2 ::= SEQUENCE {
 *      certs        SEQUENCE OF ESSCertIDv2,
 *      policies     SEQUENCE OF PolicyInformation OPTIONAL
 * }
 */
export class SigningCertificateV2 extends PkiBase<SigningCertificateV2> {
    certs: ESSCertIDv2[]
    policies?: PolicyInformation[]

    constructor(options: {
        certs: ESSCertIDv2[]
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

    static fromAsn1(asn1: Asn1BaseBlock): SigningCertificateV2 {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                'Invalid SigningCertificateV2: expected 1 to 2 elements',
            )
        }

        const certsAsn1 = values[0]
        if (!(certsAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid SigningCertificateV2: expected SEQUENCE for certs',
            )
        }

        const certs = certsAsn1.valueBlock.value.map((c) =>
            ESSCertIDv2.fromAsn1(c),
        )

        let policies: PolicyInformation[] | undefined
        if (values.length > 1) {
            const policiesAsn1 = values[1]
            if (!(policiesAsn1 instanceof asn1js.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid SigningCertificateV2: expected SEQUENCE for policies',
                )
            }

            policies = policiesAsn1.valueBlock.value.map((p) =>
                PolicyInformation.fromAsn1(p),
            )
        }

        return new SigningCertificateV2({ certs, policies })
    }

    static async fromCertificates(options: {
        certificates: Certificate[]
        policies?: PolicyInformation[]
    }): Promise<SigningCertificateV2> {
        const hashAlgorithm = AlgorithmIdentifier.digestAlgorithm('SHA-256')
        const essCerts = await Promise.all(
            options.certificates.map(
                async (cert) =>
                    new ESSCertIDv2({
                        hashAlgorithm,
                        certHash: await hashAlgorithm.digest(cert),
                        issuerSerial: cert.getIssuerSerial(),
                    }),
            ),
        )

        return new SigningCertificateV2({
            certs: essCerts,
            policies: options.policies,
        })
    }
}
