import { describe, expect, test } from 'vitest'
import { rememberOriginalEncoding, signedBytes } from './OriginalEncoding.js'
import { derToAsn1 } from './PkiBase.js'
import { Certificate } from '../x509/Certificate.js'
import { TBSCertificate } from '../x509/TBSCertificate.js'
import { pkitsFiles } from '../../test-fixtures/pkits/pkits.js'

const der = (name: string) =>
    Uint8Array.from(atob(pkitsFiles[name]), (c) => c.charCodeAt(0))

describe('OriginalEncoding', () => {
    // NIST PKITS 4.2.4: notBefore is a GeneralizedTime in 2002, which pki-lite
    // re-encodes as UTCTime, so the re-encoded TBSCertificate differs from the signed one
    const parse = () =>
        Certificate.fromDer(der('ValidGeneralizedTimenotBeforeDateTest4EE'))

    test('signedBytes returns the bytes a parsed structure came from', () => {
        const original = der('ValidGeneralizedTimenotBeforeDateTest4EE')
        const certificate = parse()
        const tbs = signedBytes(certificate.tbsCertificate)
        expect(certificate.tbsCertificate.toDer()).not.toEqual(tbs)
        // the TBSCertificate is the first element of the certificate's SEQUENCE
        const asText = (b: Uint8Array) => Array.from(b).join(',')
        expect(asText(original)).toContain(asText(tbs))
    })

    test('a certificate whose re-encoding differs still verifies', async () => {
        const certificate = parse()
        const issuer = Certificate.fromDer(der('GoodCACert'))
        expect(await certificate.isIssuedBy(issuer)).toBe(true)
    })

    test('a modified structure uses its current encoding', () => {
        const certificate = parse()
        const tbs = certificate.tbsCertificate
        tbs.validity.notAfter = new Date('2040-01-01T00:00:00Z')
        expect(signedBytes(tbs)).toEqual(tbs.toDer())
    })

    test('structures built in code use their encoding', () => {
        const tbs = parse().tbsCertificate
        const copy = TBSCertificate.fromAsn1(derToAsn1(tbs.toDer()))
        expect(signedBytes(copy)).toEqual(copy.toDer())
    })

    test('the remembered bytes take no part in JSON', () => {
        const tbs = parse().tbsCertificate
        rememberOriginalEncoding(tbs, derToAsn1(tbs.toDer()))
        expect(JSON.stringify(Object.keys(tbs))).not.toContain('original')
        expect(
            Object.getOwnPropertySymbols(tbs).every(
                (s) => !Object.getOwnPropertyDescriptor(tbs, s)!.enumerable,
            ),
        ).toBe(true)
    })
})
