import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { ExtKeyUsage } from '../x509/extensions/ExtKeyUsage.js'
import { ResponderID } from './ResponderID.js'
import { Certificate } from '../x509/Certificate.js'
import { ResponseData } from './ResponseData.js'
import { BitString } from '../asn1/BitString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * BasicOCSPResponse ::= SEQUENCE {
 *     tbsResponseData      ResponseData,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signature            BIT STRING,
 *     certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
 * }
 */
export class BasicOCSPResponse extends PkiBase<BasicOCSPResponse> {
    tbsResponseData: ResponseData
    signatureAlgorithm: AlgorithmIdentifier
    signature: BitString
    certs?: Certificate[]

    constructor(options: {
        tbsResponseData: ResponseData
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array<ArrayBuffer> | BitString
        certs?: Certificate[]
    }) {
        super()
        this.tbsResponseData = options.tbsResponseData
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signature = new BitString({ value: options.signature })
        this.certs = options.certs
    }

    /**
     * Verifies that the response comes from `issuer`, the CA whose certificates it gives
     * the status of (RFC 6960 4.2.2.2): it is signed either by the CA itself or by a
     * delegated responder, a certificate in the response that the CA issued with
     * extendedKeyUsage OCSPSigning (valid at `time`). The responderID must name the
     * signer, and the signature must verify.
     *
     * This checks the response, not the CA: whether `issuer` is trusted is up to
     * certification path validation (CertificateValidator).
     *
     * @param issuer The certificate of the CA that issued the certificates in question
     * @param options.time When a delegated responder's certificate must be valid (default now)
     * @returns Whether the response is signed by the CA or a responder it authorised
     */
    async verify(
        issuer: Certificate,
        options: { time?: Date } = {},
    ): Promise<boolean> {
        const time = options.time ?? new Date()
        const algorithm = SignatureAlgorithmIdentifier.fromDer(
            this.signatureAlgorithm.toDer(),
        )
        const signed = this.tbsResponseData.toDer()
        for (const signer of [issuer, ...(this.certs ?? [])]) {
            if (!(await this.namesResponder(signer))) continue
            if (
                !signer.equals(issuer) &&
                !(await isDelegatedResponder(signer, issuer, time))
            ) {
                continue
            }
            try {
                if (
                    await algorithm.verify(
                        signed,
                        this.signature.bytes,
                        signer.getSubjectPublicKeyInfo(),
                    )
                ) {
                    return true
                }
            } catch {
                // an unsupported algorithm or a malformed key: not a usable signature
            }
        }
        return false
    }

    /** Whether the responderID names `certificate`: by subject, or by key hash (SHA-1). */
    private async namesResponder(certificate: Certificate): Promise<boolean> {
        const responderID = this.tbsResponseData.responderID
        if (responderID instanceof ResponderID.byKey) {
            // KeyHash: SHA-1 of the key bits (RFC 6960 4.2.1)
            const keyHash = await AlgorithmIdentifier.digestAlgorithm(
                'SHA-1',
            ).digest(
                certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
                    .bytes,
            )
            return (
                responderID.bytes.length === keyHash.length &&
                responderID.bytes.every((byte, i) => byte === keyHash[i])
            )
        }
        return responderID.equals(certificate.tbsCertificate.subject)
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [
            this.tbsResponseData.toAsn1(),
            this.signatureAlgorithm.toAsn1(),
            this.signature.toAsn1(),
        ]

        if (this.certs && this.certs.length > 0) {
            const certsSequence = new asn1js.Sequence({
                value: this.certs.map((cert) => cert.toAsn1()),
            })

            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [certsSequence],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): BasicOCSPResponse {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (
            sequence.valueBlock.value.length < 3 ||
            sequence.valueBlock.value.length > 4
        ) {
            throw new Asn1ParseError(
                'Invalid BasicOCSPResponse: expected 3 or 4 elements',
            )
        }

        const tbsResponseData = ResponseData.fromAsn1(
            sequence.valueBlock.value[0],
        )
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            sequence.valueBlock.value[1],
        )
        const signatureBlock = sequence.valueBlock.value[2] as asn1js.BitString
        const signature = new Uint8Array(signatureBlock.valueBlock.valueHexView)

        let certs: Certificate[] | undefined = undefined

        if (sequence.valueBlock.value.length > 3) {
            const certsContainer = sequence.valueBlock
                .value[3] as asn1js.Constructed
            if (
                certsContainer.idBlock.tagClass !== 3 ||
                certsContainer.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid BasicOCSPResponse: expected [0] tag for certs',
                )
            }

            const certsSequence = certsContainer.valueBlock
                .value[0] as asn1js.Sequence
            certs = certsSequence.valueBlock.value.map((cert) =>
                Certificate.fromAsn1(cert),
            )
        }

        return new BasicOCSPResponse({
            tbsResponseData,
            signatureAlgorithm,
            signature,
            certs,
        })
    }
}

/**
 * Whether `certificate` is a responder `issuer` authorised to sign OCSP responses for it
 * (RFC 6960 4.2.2.2): issued by `issuer`, with extendedKeyUsage id-kp-OCSPSigning, and
 * valid at `time`.
 */
async function isDelegatedResponder(
    certificate: Certificate,
    issuer: Certificate,
    time: Date,
): Promise<boolean> {
    const { notBefore, notAfter } = certificate.tbsCertificate.validity
    if (time < notBefore || time > notAfter) return false
    const eku = certificate.getExtensionByName('EXTENDED_KEY_USAGE')
    if (
        !eku ||
        !eku.extnValue
            .parseAs(ExtKeyUsage)
            .some((purpose) => purpose.value === OIDs.EKU.OCSP_SIGNING)
    ) {
        return false
    }
    try {
        return await certificate.isIssuedBy(issuer)
    } catch {
        return false
    }
}
