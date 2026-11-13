import { Extension } from '../src/x509/Extension.js'
import { OIDs } from '../src/core/OIDs.js'
import { Certificate } from '../src/x509/Certificate.js'
import { PrivateKeyInfo } from '../src/keys/PrivateKeyInfo.js'
import { OCSPResponse } from '../src/ocsp/OCSPResponse.js'
import { rsaSigningKeys } from './signing-keys/rsa-2048/index.js'
import { rsaSigningKeys as otherKeys } from './signing-keys/rsa-3072/index.js'

const DAY = 24 * 60 * 60 * 1000

/**
 * A small PKI for OCSP unit tests (browser-safe, from the fixture keys): a CA, delegated
 * responders (extendedKeyUsage OCSPSigning; one also with id-pkix-ocsp-nocheck), a certificate of the CA without OCSPSigning,
 * an expired responder, another CA with the same name as `ca` but another key, and a leaf.
 */
export async function ocspTestPki() {
    const caKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
    const caPublicKey = Certificate.fromPem(rsaSigningKeys.certPem)
        .tbsCertificate.subjectPublicKeyInfo
    const otherKey = PrivateKeyInfo.fromPem(otherKeys.privateKeyPem)
    const otherPublicKey = Certificate.fromPem(otherKeys.certPem).tbsCertificate
        .subjectPublicKeyInfo

    const selfSigned = (key: PrivateKeyInfo, publicKey: typeof caPublicKey) =>
        Certificate.builder()
            .setSubject('CN=OCSP Unit CA')
            .setPublicKey(publicKey)
            .setPrivateKey(key)
            .setValidityPeriod(new Date('2024-01-01'), new Date('2034-01-01'))
            .addBasicConstraints(true)
            .addKeyUsage({ keyCertSign: true, cRLSign: true })
            .selfSign()
    const ca = await selfSigned(caKey, caPublicKey)
    const impostorCa = await selfSigned(otherKey, otherPublicKey)

    const issue = (
        subject: string,
        serial: number,
        options: {
            ocspSigning?: boolean
            noCheck?: boolean
            notAfter?: Date
        } = {},
    ) => {
        const builder = Certificate.builder()
            .setSubject(`CN=${subject}`)
            .setPublicKey(otherPublicKey)
            .setIssuer(ca)
            .setIssuerPrivateKey(caKey)
            .setSerialNumber(serial)
            .setValidityPeriod(
                new Date('2024-01-01'),
                options.notAfter ?? new Date('2034-01-01'),
            )
        if (options.ocspSigning)
            builder.addExtendedKeyUsage({ ocspSigning: true })
        if (options.noCheck) {
            // id-pkix-ocsp-nocheck, whose value is NULL
            builder.addExtension(
                new Extension({
                    extnID: OIDs.PKIX.ID_PKIX_OCSP_NOCHECK,
                    extnValue: new Uint8Array([0x05, 0x00]),
                }),
            )
        }
        return builder.sign()
    }

    const responder = await issue('Responder', 2, { ocspSigning: true })
    const noCheckResponder = await issue('No Check Responder', 5, {
        ocspSigning: true,
        noCheck: true,
    })
    const notResponder = await issue('Not A Responder', 3)
    const expiredResponder = await issue('Expired Responder', 4, {
        ocspSigning: true,
        notAfter: new Date('2025-01-01'),
    })
    const leaf = await issue('Leaf', 1001)

    /** A response about `leaf`, signed with `key` by `signer` (named as responder) */
    const respond = (options: {
        signer: Certificate
        key: PrivateKeyInfo
        status?: 'good' | 'revoked'
        include?: Certificate[]
        thisUpdate?: Date
        nextUpdate?: Date
    }) => {
        const builder = OCSPResponse.builder()
            .setPrivateKey(options.key)
            .setResponderFromCertificate(options.signer)
            .addResponse(ca, leaf, options.status ?? 'good', {
                thisUpdate: options.thisUpdate ?? new Date(Date.now() - DAY),
                nextUpdate: options.nextUpdate ?? new Date(Date.now() + DAY),
                revocationTime: new Date('2025-06-01T00:00:00Z'),
                revocationReason: 1,
            })
        for (const certificate of options.include ?? []) {
            builder.addCertificate(certificate)
        }
        return builder.build()
    }

    return {
        ca,
        caKey,
        impostorCa,
        otherKey,
        responder,
        noCheckResponder,
        notResponder,
        expiredResponder,
        leaf,
        respond,
    }
}
