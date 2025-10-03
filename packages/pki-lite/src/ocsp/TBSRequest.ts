import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { Name } from '../x509/Name.js'
import { Extension } from '../x509/Extension.js'
import { Request } from './Request.js'
import { Certificate } from '../x509/Certificate.js'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * TBSRequest ::= SEQUENCE {
 *     version             [0] EXPLICIT Version DEFAULT v1,
 *     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
 *     requestList         SEQUENCE OF Request,
 *     requestExtensions   [2] EXPLICIT Extensions OPTIONAL
 * }
 */
export class TBSRequest extends PkiBase<TBSRequest> {
    version: number
    requestorName?: Name
    requestList: Request[]
    requestExtensions?: Extension[]

    constructor(options: {
        version?: number
        requestorName?: Name
        requestList: Request[]
        requestExtensions?: Extension[]
    }) {
        super()
        this.version = options.version ?? 0
        this.requestorName = options.requestorName
        this.requestList = options.requestList
        this.requestExtensions = options.requestExtensions
    }

    static async forCertificate(options: {
        certificate: Certificate
        issuerCertificate: Certificate
    }): Promise<TBSRequest> {
        const { certificate, issuerCertificate } = options
        const hashAlgorithm = AlgorithmIdentifier.digestAlgorithm('SHA-256')

        const request = new Request({
            reqCert: new CertID({
                hashAlgorithm: hashAlgorithm,
                issuerKeyHash: await hashAlgorithm.digest(
                    issuerCertificate.getSubjectPublicKeyInfo()
                        .subjectPublicKey,
                ),
                issuerNameHash: await hashAlgorithm.digest(
                    issuerCertificate.tbsCertificate.issuer.toDer(),
                ),
                serialNumber: certificate.tbsCertificate.serialNumber,
            }),
        })

        return new TBSRequest({
            requestList: [request],
        })
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = []

        // Only include version if it's not the default (v1=0)
        if (this.version !== 0) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [new asn1js.Integer({ value: this.version })],
                }),
            )
        }

        // Include requestorName if provided
        if (this.requestorName) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    value: [
                        new asn1js.Constructed({
                            idBlock: {
                                tagClass: 3, // CONTEXT-SPECIFIC
                                tagNumber: 4, // [4] - DirectoryName
                            },
                            value: [this.requestorName.toAsn1()],
                        }),
                    ],
                }),
            )
        }

        // Add requestList (required)
        const requestListSequence = new asn1js.Sequence({
            value: this.requestList.map((req) => req.toAsn1()),
        })
        values.push(requestListSequence)

        // Include requestExtensions if provided
        if (this.requestExtensions && this.requestExtensions.length > 0) {
            const extensions = new asn1js.Sequence({
                value: this.requestExtensions.map((ext) => ext.toAsn1()),
            })

            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 2, // [2]
                    },
                    value: [extensions],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): TBSRequest {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        let currentIndex = 0
        let version = 0 // Default is v1 (0)
        let requestorName: Name | undefined = undefined
        let requestList: Request[] = []
        let requestExtensions: Extension[] | undefined = undefined

        // Check for version [0]
        if (
            currentIndex < sequence.valueBlock.value.length &&
            sequence.valueBlock.value[currentIndex] instanceof
                asn1js.Constructed &&
            (sequence.valueBlock.value[currentIndex] as asn1js.Constructed)
                .idBlock.tagNumber === 0
        ) {
            const versionContainer = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            const versionInt = versionContainer.valueBlock
                .value[0] as asn1js.Integer
            version = versionInt.valueBlock.valueDec as number
            currentIndex++
        }

        // Check for requestorName [1]
        if (
            currentIndex < sequence.valueBlock.value.length &&
            sequence.valueBlock.value[currentIndex] instanceof
                asn1js.Constructed &&
            (sequence.valueBlock.value[currentIndex] as asn1js.Constructed)
                .idBlock.tagNumber === 1
        ) {
            const requestorNameContainer = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            const generalName = requestorNameContainer.valueBlock
                .value[0] as asn1js.Constructed

            // Only handle DirectoryName (tag 4) for now
            if (generalName.idBlock.tagNumber === 4) {
                requestorName = Name.fromAsn1(generalName.valueBlock.value[0])
            }

            currentIndex++
        }

        // Get requestList (required)
        if (currentIndex < sequence.valueBlock.value.length) {
            const requestListSequence = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Sequence
            requestList = requestListSequence.valueBlock.value.map((req) =>
                Request.fromAsn1(req),
            )
            currentIndex++
        } else {
            throw new Asn1ParseError('Invalid TBSRequest: missing requestList')
        }

        // Check for requestExtensions [2]
        if (
            currentIndex < sequence.valueBlock.value.length &&
            sequence.valueBlock.value[currentIndex] instanceof
                asn1js.Constructed &&
            (sequence.valueBlock.value[currentIndex] as asn1js.Constructed)
                .idBlock.tagNumber === 2
        ) {
            const extensionsContainer = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            const extensionsSequence = extensionsContainer.valueBlock
                .value[0] as asn1js.Sequence
            requestExtensions = extensionsSequence.valueBlock.value.map((ext) =>
                Extension.fromAsn1(ext),
            )
        }

        return new TBSRequest({
            requestList,
            version,
            requestorName,
            requestExtensions,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): TBSRequest {
        return TBSRequest.fromAsn1(derToAsn1(der))
    }
}
