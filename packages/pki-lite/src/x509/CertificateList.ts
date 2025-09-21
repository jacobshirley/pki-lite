import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    pemToDer,
    PkiBase,
} from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { TBSCertList } from './TBSCertList.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { Name } from './Name.js'
import { RevokedCertificate } from './RevokedCertificate.js'
import { AsymmetricEncryptionAlgorithmParams } from '../core/crypto/types.js'
import { BitString } from '../asn1/BitString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a Certificate Revocation List (CRL).
 *
 * @asn
 * ```asn
 * CertificateList  ::=  SEQUENCE  {
 *      tbsCertList          TBSCertList,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING
 * }
 * ```
 */
export class CertificateList extends PkiBase<CertificateList> {
    tbsCertList: TBSCertList
    signatureAlgorithm: AlgorithmIdentifier
    signatureValue: BitString

    constructor(options: {
        tbsCertList: TBSCertList
        signatureAlgorithm: AlgorithmIdentifier
        signatureValue: Uint8Array | BitString
    }) {
        super()

        this.tbsCertList = options.tbsCertList
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signatureValue = new BitString({
            value: options.signatureValue,
        })
    }

    get pemHeader() {
        return 'X509 CRL'
    }

    static async createEmpty(options: {
        issuer: Name
        privateKey: PrivateKeyInfo
        signatureAlgorithmParams?: AsymmetricEncryptionAlgorithmParams
    }): Promise<CertificateList> {
        const { issuer } = options
        const signatureAlgorithmParams: AsymmetricEncryptionAlgorithmParams =
            options?.signatureAlgorithmParams ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: {
                    hash: 'SHA-256',
                },
            }
        const signatureAlgorithm = AlgorithmIdentifier.signatureAlgorithm(
            signatureAlgorithmParams,
        )

        // No revoked certificates for now
        const revokedCertificates: RevokedCertificate[] = []

        // Set thisUpdate to now, nextUpdate to +30 days
        const thisUpdate = new Date()
        const nextUpdate = new Date(
            thisUpdate.getTime() + 30 * 24 * 60 * 60 * 1000,
        )

        // TBSCertList version 1 (v2), as per RFC if extensions present
        const tbsCertList = new TBSCertList({
            version: 1,
            signature: signatureAlgorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates,
        })

        return new CertificateList({
            tbsCertList,
            signatureAlgorithm,
            signatureValue: await signatureAlgorithm.sign(
                tbsCertList,
                options.privateKey,
            ),
        })
    }

    /**
     * Converts the CRL to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        // Create the main CertificateList sequence
        return new asn1js.Sequence({
            value: [
                this.tbsCertList.toAsn1(),
                this.signatureAlgorithm.toAsn1(),
                this.signatureValue.toAsn1(),
            ],
        })
    }

    /**
     * Creates a CertificateList from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The CertificateList object
     */
    static fromAsn1(asn1: Asn1BaseBlock): CertificateList {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // Define a type for the valueBlock structure we need to access
        interface ValueBlock {
            value: asn1js.BaseBlock[]
        }

        const values = (asn1.valueBlock as unknown as ValueBlock).value
        if (values.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        // Extract tbsCertList
        if (!(values[0] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for tbsCertList',
            )
        }
        const tbsCertList = TBSCertList.fromAsn1(values[0])

        // Extract signatureAlgorithm
        if (!(values[1] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
            )
        }
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[1])

        // Extract signatureValue
        if (!(values[2] instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING for signatureValue',
            )
        }
        const signatureValue = new Uint8Array(values[2].valueBlock.valueHexView)

        return new CertificateList({
            tbsCertList,
            signatureAlgorithm,
            signatureValue,
        })
    }

    static fromDer(der: Uint8Array): CertificateList {
        return CertificateList.fromAsn1(derToAsn1(der))
    }

    static fromPem(pem: string): CertificateList {
        return CertificateList.fromDer(pemToDer(pem, 'X509 CRL'))
    }

    static async fetch(url: string): Promise<CertificateList> {
        const res = await fetch(url)
        if (!res.ok) {
            throw new Error(
                `Failed to fetch CRL from ${url}: ${res.statusText}`,
            )
        }
        const der = new Uint8Array(await res.arrayBuffer())
        return CertificateList.fromDer(der)
    }
}
