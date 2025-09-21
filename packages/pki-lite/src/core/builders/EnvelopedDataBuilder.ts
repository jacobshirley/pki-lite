import {
    AlgorithmIdentifier,
    KeyEncryptionAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../../x509/Certificate.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    SymmetricEncryptionAlgorithmParams,
} from '../crypto/types.js'
import { EncryptedContentInfo } from '../../pkcs7/EncryptedContentInfo.js'
import { EnvelopedData } from '../../pkcs7/EnvelopedData.js'
import { IssuerAndSerialNumber } from '../../pkcs7/IssuerAndSerialNumber.js'
import { OIDs } from '../OIDs.js'
import { RecipientInfo } from '../../pkcs7/recipients/RecipientInfo.js'
import { KeyTransRecipientInfo } from '../../pkcs7/recipients/KeyTransRecipientInfo.js'
import { AsyncBuilder } from './types.js'
import { RSAESOAEPParams } from '../../algorithms/RSAESOAEPParams.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { ObjectIdentifierString } from '../PkiBase.js'
import { OriginatorInfo } from '../../pkcs7/recipients/OriginatorInfo.js'
import { RevocationInfoChoice } from '../../revocation/RevocationInfoChoice.js'
import { OtherRevocationInfoFormat } from '../../revocation/OtherRevocationInfoFormat.js'
import { OCSPResponse } from '../../ocsp/OCSPResponse.js'
import { CertificateList } from '../../x509/CertificateList.js'
import { CertificateChoices } from '../../x509/CertificateChoices.js'
import { OtherRecipientInfo } from '../../pkcs7/recipients/OtherRecipientInfo.js'

export type EnvelopedDataBuilderRecipient = {
    certificate: Certificate
    keyEncryptionAlgorithm?: AsymmetricEncryptionAlgorithmParams
}

export class EnvelopedDataBuilder implements AsyncBuilder<EnvelopedData> {
    static readonly DEFAULT_KEY_ENCRYPTION_ALGORITHM =
        new KeyEncryptionAlgorithmIdentifier({
            algorithm: OIDs.RSA.RSAES_OAEP,
            parameters: RSAESOAEPParams.createDefault(),
        })
    data?: Uint8Array
    contentType: ObjectIdentifier = new ObjectIdentifier({
        value: OIDs.PKCS7.DATA,
    })
    recipients: EnvelopedDataBuilderRecipient[] = []
    contentEncryptionAlgorithm?: SymmetricEncryptionAlgorithmParams
    certificates?: CertificateChoices[]
    crls: RevocationInfoChoice[] = []

    setData(
        data: Uint8Array | string,
        contentType?: ObjectIdentifierString,
    ): this {
        this.data =
            typeof data === 'string' ? new TextEncoder().encode(data) : data

        if (contentType) {
            this.contentType = new ObjectIdentifier({ value: contentType })
        }

        return this
    }

    setContentType(type: ObjectIdentifier | ObjectIdentifierString): this {
        this.contentType = new ObjectIdentifier({
            value: type,
        })
        return this
    }

    setContentEncryptionAlgorithm(
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): this {
        this.contentEncryptionAlgorithm = algorithm
        return this
    }

    addRecipient(...recipient: EnvelopedDataBuilderRecipient[]): this {
        this.recipients.push(...recipient)
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

    get originatorInfo(): OriginatorInfo | undefined {
        if (!this.certificates || this.certificates.length === 0) {
            return undefined
        }

        return new OriginatorInfo({
            certs: this.certificates,
            crls: this.crls,
        })
    }

    /**
     * If originatorInfo is
      present, then version shall be 2.  If any of the RecipientInfo
      structures included have a version other than 0, then the version
      shall be 2.  If unprotectedAttrs is present, then version shall be
      2.  If originatorInfo is absent, all of the RecipientInfo
      structures are version 0, and unprotectedAttrs is absent, then
      version shall be 0.
     */
    private getVersion(recipients: RecipientInfo[]): number {
        if (this.originatorInfo) {
            return 2
        }

        if (
            recipients.some(
                (r) => r instanceof OtherRecipientInfo || r.version !== 0,
            )
        ) {
            return 2
        }

        return 0
    }

    async build(): Promise<EnvelopedData> {
        const data = this.data
        if (!data) {
            throw new Error('No data to encrypt')
        }

        if (this.recipients.length === 0) {
            throw new Error('At least one recipient must be specified')
        }

        if (!this.contentEncryptionAlgorithm) {
            this.contentEncryptionAlgorithm = {
                type: 'AES_256_CBC',
                params: {
                    nonce: AlgorithmIdentifier.randomBytes(16),
                },
            }
        }

        const contentEncryptionAlgorithm =
            AlgorithmIdentifier.contentEncryptionAlgorithm(
                this.contentEncryptionAlgorithm,
            )

        const contentEncryptionKey = contentEncryptionAlgorithm.generateKey()

        const encryptedContent = await contentEncryptionAlgorithm.encrypt(
            data,
            contentEncryptionKey,
        )

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: this.contentType,
            contentEncryptionAlgorithm,
            encryptedContent: encryptedContent,
        })

        const recipientInfos: RecipientInfo[] = await Promise.all(
            this.recipients.map(async (recipient) => {
                const keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier =
                    recipient.keyEncryptionAlgorithm
                        ? AlgorithmIdentifier.keyEncryptionAlgorithm(
                              recipient.keyEncryptionAlgorithm,
                          )
                        : EnvelopedDataBuilder.DEFAULT_KEY_ENCRYPTION_ALGORITHM

                const issuerAndSerialNumber = new IssuerAndSerialNumber({
                    issuer: recipient.certificate.tbsCertificate.issuer,
                    serialNumber:
                        recipient.certificate.tbsCertificate.serialNumber,
                })

                const publicKey =
                    recipient.certificate.tbsCertificate.subjectPublicKeyInfo

                const encryptedKey = await keyEncryptionAlgorithm.encrypt(
                    contentEncryptionKey,
                    publicKey,
                )

                const ktri = new KeyTransRecipientInfo({
                    rid: issuerAndSerialNumber,
                    keyEncryptionAlgorithm,
                    encryptedKey,
                })

                return ktri
            }),
        )

        return new EnvelopedData({
            version: this.getVersion(recipientInfos),
            recipientInfos,
            encryptedContentInfo,
        })
    }
}
