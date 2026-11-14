import { beforeAll, describe, expect, test } from 'vitest'
import { checkCertificateProfile } from './CertificateProfile.js'
import { OIDs } from './OIDs.js'
import { Certificate } from '../x509/Certificate.js'
import { Extension } from '../x509/Extension.js'
import { GeneralName } from '../x509/GeneralName.js'
import { Integer } from '../asn1/Integer.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import {
    GeneralSubtree,
    NameConstraints,
} from '../x509/extensions/NameConstraints.js'
import { ExtKeyUsage } from '../x509/extensions/ExtKeyUsage.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'

const key = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
const publicKey = Certificate.fromPem(rsaSigningKeys.certPem).tbsCertificate
    .subjectPublicKeyInfo
const keyId = new Uint8Array([1, 2, 3, 4])

// A conforming CA and leaf (the checks read the certificate only, so tests change one
// field or extension of a fresh copy and look for the matching problem)
let ca: Certificate
let leaf: Certificate
beforeAll(async () => {
    ca = await Certificate.builder()
        .setSubject('CN=Profile CA')
        .setPublicKey(publicKey)
        .setPrivateKey(key)
        .setSerialNumber(1)
        .setValidityDays(1)
        .addBasicConstraints(true)
        .addKeyUsage({ keyCertSign: true, cRLSign: true })
        .addSubjectKeyIdentifier(keyId)
        .selfSign()
    leaf = await Certificate.builder()
        .setSubject('CN=leaf.example')
        .setPublicKey(publicKey)
        .setIssuer(ca)
        .setIssuerPrivateKey(key)
        .setSerialNumber(2)
        .setValidityDays(1)
        .addKeyUsage({ digitalSignature: true })
        .addAuthorityKeyIdentifier(keyId)
        .addSubjectAltName('leaf.example', '*.leaf.example')
        .sign()
})

const copy = (cert: Certificate) => Certificate.fromDer(cert.toDer())
const extension = (cert: Certificate, oid: string) =>
    cert.tbsCertificate.extensions!.find((e) => e.extnID.value === oid)!
const problems = (cert: Certificate, trustAnchor = false) =>
    checkCertificateProfile(cert, { trustAnchor }).join('; ')

describe('checkCertificateProfile (RFC 5280 section 4)', () => {
    test('conforming certificates have no problems', () => {
        expect(problems(ca)).toBe('')
        expect(problems(leaf)).toBe('')
    })

    test('duplicate extensions', () => {
        const cert = copy(leaf)
        cert.tbsCertificate.extensions!.push(
            extension(cert, OIDs.EXTENSION.KEY_USAGE),
        )
        expect(problems(cert)).toContain('appears twice')
    })

    test('serial numbers: positive, at most 20 octets; not checked for a trust anchor', () => {
        const cert = copy(leaf)
        cert.tbsCertificate.serialNumber = new Integer({ value: 0 })
        expect(problems(cert)).toContain('not positive')
        cert.tbsCertificate.serialNumber = new Integer({ value: -5n })
        expect(problems(cert)).toContain('not positive')
        cert.tbsCertificate.serialNumber = new Integer({
            value: new Uint8Array(21).fill(1),
        })
        expect(problems(cert)).toContain('longer than 20 octets')

        const anchor = copy(ca)
        anchor.tbsCertificate.serialNumber = new Integer({ value: 0 })
        expect(problems(anchor, true)).toBe('')
    })

    test('authorityKeyIdentifier: present unless self-signed, never critical', () => {
        const cert = copy(leaf)
        cert.tbsCertificate.extensions = cert.tbsCertificate.extensions!.filter(
            (e) => e.extnID.value !== OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER,
        )
        expect(problems(cert)).toContain('no authorityKeyIdentifier')
        // a trust anchor that is not self-signed is not required to have one
        expect(problems(cert, true)).not.toContain('authorityKeyIdentifier')

        const critical = copy(leaf)
        extension(critical, OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER).critical =
            true
        expect(problems(critical)).toContain(
            'authorityKeyIdentifier extension is critical',
        )
    })

    test('subjectKeyIdentifier in CAs, never critical', () => {
        const missing = copy(ca)
        missing.tbsCertificate.extensions =
            missing.tbsCertificate.extensions!.filter(
                (e) => e.extnID.value !== OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER,
            )
        expect(problems(missing, true)).toContain(
            'without subjectKeyIdentifier',
        )
        const critical = copy(ca)
        extension(critical, OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER).critical =
            true
        expect(problems(critical)).toContain(
            'subjectKeyIdentifier extension is critical',
        )
    })

    test('basicConstraints critical in a CA; keyCertSign only in a CA', () => {
        const cert = copy(ca)
        extension(cert, OIDs.EXTENSION.BASIC_CONSTRAINTS).critical = false
        expect(problems(cert)).toContain(
            'basicConstraints extension of a CA is not critical',
        )

        const signer = copy(leaf)
        signer.tbsCertificate.extensions =
            signer.tbsCertificate.extensions!.map((e) =>
                e.extnID.value === OIDs.EXTENSION.KEY_USAGE
                    ? Extension.keyUsage({ keyCertSign: true })
                    : e,
            )
        expect(problems(signer)).toContain(
            'keyCertSign in a certificate that is not a CA',
        )
    })

    test('subjects and subjectAltNames', () => {
        const emptyCa = copy(ca)
        emptyCa.tbsCertificate.subject = new RDNSequence()
        expect(problems(emptyCa)).toContain(
            'a CA certificate with an empty subject',
        )

        const emptyLeaf = copy(leaf)
        emptyLeaf.tbsCertificate.subject = new RDNSequence()
        expect(problems(emptyLeaf)).toContain(
            'without a critical subjectAltName',
        )
        extension(emptyLeaf, OIDs.EXTENSION.SUBJECT_ALT_NAME).critical = true
        expect(problems(emptyLeaf)).toBe('')

        for (const name of [
            new GeneralName.dNSName({ value: 'under_score.example' }),
            new GeneralName.dNSName({ value: '.example.com' }),
            new GeneralName.rfc822Name({ value: 'a@b@example.com' }),
            new GeneralName.iPAddress({ bytes: new Uint8Array(5) }),
        ]) {
            const cert = copy(leaf)
            cert.tbsCertificate.extensions =
                cert.tbsCertificate.extensions!.map((e) =>
                    e.extnID.value === OIDs.EXTENSION.SUBJECT_ALT_NAME
                        ? Extension.subjectAltName([name])
                        : e,
                )
            expect(problems(cert), name.toString()).toContain(
                'a malformed subjectAltName',
            )
        }
    })

    test('nameConstraints: in a CA, critical, non-empty, well-formed', () => {
        const constraints = (permitted: GeneralSubtree[], critical = true) =>
            new Extension({
                extnID: OIDs.EXTENSION.NAME_CONSTRAINTS,
                critical,
                extnValue: new NameConstraints({
                    permittedSubtrees: permitted,
                }),
            })
        const subtree = (dns: string) =>
            new GeneralSubtree({
                base: new GeneralName.dNSName({ value: dns }),
            })
        const withConstraints = (cert: Certificate, ext: Extension) => {
            const out = copy(cert)
            out.tbsCertificate.extensions!.push(ext)
            return problems(out)
        }

        expect(withConstraints(ca, constraints([subtree('example.com')]))).toBe(
            '',
        )
        expect(
            withConstraints(leaf, constraints([subtree('example.com')])),
        ).toContain('nameConstraints in a certificate that is not a CA')
        expect(
            withConstraints(ca, constraints([subtree('example.com')], false)),
        ).toContain('nameConstraints extension is not critical')
        expect(withConstraints(ca, constraints([]))).toContain(
            'empty permittedSubtrees',
        )
        expect(
            withConstraints(ca, constraints([subtree('.example.com')])),
        ).toContain("a malformed dNSName constraint '.example.com'")
    })

    test('policyConstraints critical, extKeyUsage non-empty, authorityInfoAccess non-critical', () => {
        const pc = copy(ca)
        pc.tbsCertificate.extensions!.push(
            Extension.policyConstraints({ requireExplicitPolicy: 0 }),
        )
        extension(pc, OIDs.EXTENSION.POLICY_CONSTRAINTS).critical = false
        expect(problems(pc)).toContain(
            'policyConstraints extension is not critical',
        )

        const eku = copy(leaf)
        eku.tbsCertificate.extensions!.push(
            new Extension({
                extnID: OIDs.EXTENSION.EXTENDED_KEY_USAGE,
                extnValue: new ExtKeyUsage(),
            }),
        )
        expect(problems(eku)).toContain('an empty extendedKeyUsage')

        const aia = copy(leaf)
        aia.tbsCertificate.extensions!.push(
            Extension.authorityInfoAccess([
                {
                    accessMethod: OIDs.AUTHORITY_INFO_ACCESS.CA_ISSUERS,
                    accessLocation: new GeneralName.uniformResourceIdentifier({
                        value: 'http://ca.example/ca.crt',
                    }),
                },
            ]),
        )
        extension(aia, OIDs.EXTENSION.AUTHORITY_INFO_ACCESS).critical = true
        expect(problems(aia)).toContain(
            'authorityInfoAccess extension is critical',
        )
    })
})
