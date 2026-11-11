import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    UniversalTag,
} from '../core/PkiBase.js'
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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        // Only include version if it's not the default (v1=0)
        if (this.version !== 0) {
            values.push(der.constructed(0, [der.integer(this.version)]))
        }

        // Include requestorName if provided
        if (this.requestorName) {
            values.push(
                der.constructed(1, [
                    der.constructed(4, [this.requestorName.toAsn1()]),
                ]),
            )
        }

        // Add requestList (required)
        const requestListSequence = der.sequence(
            this.requestList.map((req) => req.toAsn1()),
        )
        values.push(requestListSequence)

        // Include requestExtensions if provided
        if (this.requestExtensions && this.requestExtensions.length > 0) {
            const extensions = der.sequence(
                this.requestExtensions.map((ext) => ext.toAsn1()),
            )

            values.push(der.constructed(2, [extensions]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): TBSRequest {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        let currentIndex = 0
        let version = 0 // Default is v1 (0)
        let requestorName: Name | undefined = undefined
        let requestList: Request[] = []
        let requestExtensions: Extension[] | undefined = undefined

        // Check for version [0]
        if (
            currentIndex < sequence.children.length &&
            sequence.children[currentIndex]?.constructed &&
            sequence.children[currentIndex].tag === 0
        ) {
            const versionContainer = sequence.children[currentIndex]
            const versionInt = versionContainer.children[0]
            version = der.readNumber(versionInt) as number
            currentIndex++
        }

        // Check for requestorName [1]
        if (
            currentIndex < sequence.children.length &&
            sequence.children[currentIndex]?.constructed &&
            sequence.children[currentIndex].tag === 1
        ) {
            const requestorNameContainer = sequence.children[currentIndex]
            const generalName = requestorNameContainer.children[0]

            // Only handle DirectoryName (tag 4) for now
            if (generalName.tag === 4) {
                requestorName = Name.fromAsn1(generalName.children[0])
            }

            currentIndex++
        }

        // Get requestList (required)
        if (currentIndex < sequence.children.length) {
            const requestListSequence = sequence.children[currentIndex]
            requestList = requestListSequence.children.map((req) =>
                Request.fromAsn1(req),
            )
            currentIndex++
        } else {
            throw new Asn1ParseError('Invalid TBSRequest: missing requestList')
        }

        // Check for requestExtensions [2]
        if (
            currentIndex < sequence.children.length &&
            sequence.children[currentIndex]?.constructed &&
            sequence.children[currentIndex].tag === 2
        ) {
            const extensionsContainer = sequence.children[currentIndex]
            const extensionsSequence = extensionsContainer.children[0]
            requestExtensions = extensionsSequence.children.map((ext) =>
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
