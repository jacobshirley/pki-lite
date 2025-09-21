import { Attribute } from '../../x509/Attribute.js'
import { AttributeCertificate } from '../../x509/attribute-certs/AttributeCertificate.js'
import { AttributeCertificateV1 } from '../../x509/attribute-certs/AttributeCertificateV1.js'
import { Certificate } from '../../x509/Certificate.js'
import { CertificateChoices } from '../../x509/CertificateChoices.js'
import { CertificateList } from '../../x509/CertificateList.js'
import { EncapsulatedContentInfo } from '../../pkcs7/EncapsulatedContentInfo.js'
import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { IssuerAndSerialNumber } from '../../pkcs7/IssuerAndSerialNumber.js'
import { OtherCertificateFormat } from '../../x509/legacy/OtherCertificateFormat.js'
import { OtherRevocationInfoFormat } from '../../revocation/OtherRevocationInfoFormat.js'
import { OIDs } from '../OIDs.js'
import { RevocationInfoChoice } from '../../revocation/RevocationInfoChoice.js'
import { SignedData } from '../../pkcs7/SignedData.js'
import { SignerInfo } from '../../pkcs7/SignerInfo.js'
import { AsyncBuilder } from './types.js'
import { SignerIdentifier } from '../../pkcs7/SignerIdentifier.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    HashAlgorithm,
} from '../crypto/types.js'
import { OCSPResponse } from '../../ocsp/OCSPResponse.js'
import { OctetString } from '../../asn1/OctetString.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { ObjectIdentifierString } from '../PkiBase.js'
import { TimeStampReq } from '../../timestamp/TimeStampReq.js'
import { MessageImprint } from '../../timestamp/MessageImprint.js'

export type SignedDataBuilderSigner = {
    privateKeyInfo: PrivateKeyInfo
    certificate: CertificateChoices
    encryptionAlgorithm?: AsymmetricEncryptionAlgorithmParams
    signedAttrs?: Attribute[]
    unsignedAttrs?: Attribute[]
    tsa?:
        | true
        | {
              url: string
              username?: string
              password?: string
              policyId?: string
              hash?: HashAlgorithm
          }
}

export class SignedDataBuilder implements AsyncBuilder<SignedData> {
    data?: Uint8Array
    contentType: ObjectIdentifier = new ObjectIdentifier({
        value: OIDs.PKCS7.DATA,
    })
    signers: SignedDataBuilderSigner[] = []
    crls: RevocationInfoChoice[] = []
    additionalCertificates: CertificateChoices[] = []
    isDetached: boolean = false

    setData(data: Uint8Array | string, contentType?: ObjectIdentifier): this {
        this.data =
            typeof data === 'string' ? new TextEncoder().encode(data) : data
        if (contentType) {
            this.contentType = contentType
        }
        return this
    }

    setDetached(detached: boolean = true) {
        this.isDetached = detached
        return this
    }

    // Alias for setDetached
    detached = this.setDetached

    setContentType(type: ObjectIdentifier | ObjectIdentifierString): this {
        this.contentType = new ObjectIdentifier({ value: type })
        return this
    }

    addSigner(signer: SignedDataBuilderSigner): this {
        this.signers.push(signer)
        return this
    }

    addCrl(crl: CertificateList): this {
        this.crls.push(crl)
        return this
    }

    addOcsp(ocsp: OCSPResponse): this {
        this.crls.push(
            new OtherRevocationInfoFormat({
                otherRevInfoFormat: OIDs.OTHER_REV_INFO.OCSP,
                otherRevInfo: ocsp,
            }),
        )
        return this
    }

    addOtherRevocationInfo(crl: OtherRevocationInfoFormat): this {
        this.crls.push(crl)
        return this
    }

    addCertificate(...certs: Certificate[]): this {
        this.additionalCertificates.push(...certs)
        return this
    }

    get allCertificates(): CertificateChoices[] {
        return [
            ...this.signers.map((signer) => signer.certificate),
            ...this.additionalCertificates,
        ]
    }

    /**
     * Get the version of the SignedData.
     * 
     * Algorithm:
     * 
     * IF ((certificates is present) AND
            (any certificates with a type of other are present)) OR
            ((crls is present) AND
            (any crls with a type of other are present))
         THEN version MUST be 5
         ELSE
            IF (certificates is present) AND
               (any version 2 attribute certificates are present)
            THEN version MUST be 4
            ELSE
               IF ((certificates is present) AND
                  (any version 1 attribute certificates are present)) OR
                  (any SignerInfo structures are version 3) OR
                  (encapContentInfo eContentType is other than id-data)
               THEN version MUST be 3
               ELSE version MUST be 1
     *
     * @returns The version number
     */
    private getVersion(signerInfos: SignerInfo[]): number {
        if (
            this.allCertificates.some(
                (cert) => cert instanceof OtherCertificateFormat,
            )
        ) {
            return 5
        }

        if (this.crls.some((crl) => crl instanceof OtherRevocationInfoFormat)) {
            return 5
        }

        if (
            this.allCertificates.some(
                (cert) => cert instanceof AttributeCertificate,
            )
        ) {
            return 4
        }

        if (
            this.allCertificates.some(
                (cert) => cert instanceof AttributeCertificateV1,
            )
        ) {
            return 3
        }

        if (
            signerInfos.some((signer) => signer.version === 3) ||
            this.contentType.value !== OIDs.PKCS7.DATA
        ) {
            return 3
        }

        return 1
    }

    get encapContentInfo(): EncapsulatedContentInfo {
        return new EncapsulatedContentInfo({
            eContentType: this.contentType,
            eContent: this.isDetached ? undefined : this.data,
        })
    }

    async build(): Promise<SignedData> {
        const data = this.data
        if (!data) {
            throw new Error('No data to sign')
        }

        const defaultEncryption: AsymmetricEncryptionAlgorithmParams = {
            type: 'RSASSA_PKCS1_v1_5',
            params: {
                hash: 'SHA-256',
            },
        }

        const signerInfos: SignerInfo[] = await Promise.all(
            this.signers.map(async (signer) => {
                const encryptionParams =
                    signer.encryptionAlgorithm ?? defaultEncryption

                if (!('hash' in encryptionParams.params)) {
                    throw new Error(
                        'Hash algorithm must be specified in encryption parameters',
                    )
                }

                if (!(signer.certificate instanceof Certificate)) {
                    throw new Error(
                        'Only X.509 certificates are currently supported for signing',
                    )
                }

                const digestAlgorithm =
                    DigestAlgorithmIdentifier.digestAlgorithm(
                        encryptionParams.params.hash,
                    )

                const digestedData = await digestAlgorithm.digest(data)

                const signedAttributes = new SignerInfo.SignedAttributes(
                    ...(signer.signedAttrs ?? []).filter(
                        (x) =>
                            x.type.value !== OIDs.PKCS9.MESSAGE_DIGEST &&
                            x.type.value !== OIDs.PKCS7.DATA,
                    ),
                )

                signedAttributes.push(
                    new Attribute({
                        type: OIDs.PKCS9.MESSAGE_DIGEST,
                        values: [new OctetString({ bytes: digestedData })],
                    }),
                )

                signedAttributes.push(
                    new Attribute({
                        type: OIDs.PKCS9.CONTENT_TYPE,
                        values: [
                            new ObjectIdentifier({ value: this.contentType }),
                        ],
                    }),
                )

                const unsignedAttributes = new SignerInfo.UnsignedAttributes(
                    ...(signer.unsignedAttrs ?? []),
                )

                const certificate = signer.certificate

                // Extract the issuer and serial number from the certificate
                const issuerAndSerialNumber: SignerIdentifier =
                    new IssuerAndSerialNumber({
                        issuer: certificate.tbsCertificate.issuer,
                        serialNumber: certificate.tbsCertificate.serialNumber,
                    })

                const signatureAlgorithm =
                    AlgorithmIdentifier.signatureAlgorithm(encryptionParams)

                const signedAttributesDer = signedAttributes.toDer()

                const signature = await signatureAlgorithm.sign(
                    signedAttributesDer,
                    signer.privateKeyInfo,
                )

                if (signer.tsa) {
                    const tsaUrl =
                        signer.tsa === true
                            ? 'https://freetsa.org/tsr'
                            : (signer.tsa?.url ?? 'https://freetsa.org/tsr')

                    const username =
                        typeof signer.tsa === 'object'
                            ? signer.tsa.username
                            : undefined
                    const password =
                        typeof signer.tsa === 'object'
                            ? signer.tsa.password
                            : undefined
                    const hashAlgorithm =
                        typeof signer.tsa === 'object' && signer.tsa.hash
                            ? signer.tsa.hash
                            : encryptionParams.params.hash
                    const policyId =
                        typeof signer.tsa === 'object' && signer.tsa.policyId
                            ? signer.tsa.policyId
                            : undefined

                    const digestAlgorithm =
                        DigestAlgorithmIdentifier.digestAlgorithm(
                            hashAlgorithm ?? 'SHA-256',
                        )

                    const timestampResponse = await TimeStampReq.create({
                        messageImprint: new MessageImprint({
                            hashAlgorithm: digestAlgorithm,
                            hashedMessage:
                                await digestAlgorithm.digest(signature),
                        }),
                        certReq: true,
                        reqPolicy: policyId,
                    }).request({
                        url: tsaUrl,
                        username,
                        password,
                    })

                    if (!timestampResponse.timeStampToken) {
                        throw new Error(
                            'No timeStampToken in TSA response. Response: ' +
                                timestampResponse.status.statusString,
                        )
                    }

                    unsignedAttributes.push(
                        Attribute.timestampToken(
                            timestampResponse.timeStampToken,
                        ),
                    )
                }

                /*
                    version is the syntax version number.  If the SignerIdentifier is
                    the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
                    the SignerIdentifier is subjectKeyIdentifier, then the version
                    MUST be 3.

                    https://datatracker.ietf.org/doc/html/rfc5652#section-5.2
                */
                const version = 1

                return new SignerInfo({
                    version,
                    sid: issuerAndSerialNumber,
                    digestAlgorithm,
                    signatureAlgorithm,
                    signature,
                    signedAttrs: signedAttributes,
                    unsignedAttrs: unsignedAttributes,
                })
            }),
        )

        const digestAlgorithms = signerInfos.map(
            (signer) => signer.digestAlgorithm,
        )

        const signedData = new SignedData({
            version: this.getVersion(signerInfos),
            digestAlgorithms,
            encapContentInfo: this.encapContentInfo,
            signerInfos,
            certificates: this.allCertificates,
            crls: this.crls,
        })

        return signedData
    }
}
