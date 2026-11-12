import { assert, describe, expect, test } from 'vitest'
import { CertificateList } from './CertificateList.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from './Name.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'
import { TBSCertList } from './TBSCertList.js'
import { RevokedCertificate } from './RevokedCertificate.js'
import { Extension } from './Extension.js'
import { CRLReason } from './CRLReason.js'
import { pkitsFiles } from '../../test-fixtures/pkits/pkits.js'
import { Certificate } from './Certificate.js'

describe('CertificateList', () => {
    test('can be created', () => {
        const crl = createSampleCRL()

        expect(crl).toBeInstanceOf(CertificateList)
        expect(crl.tbsCertList).toBeDefined()
        expect(crl.signatureAlgorithm).toBeInstanceOf(AlgorithmIdentifier)
        expect(crl.signatureValue.bytes).toBeInstanceOf(Uint8Array<ArrayBuffer>)
    })

    test('can be converted into ASN.1', () => {
        const crl = createSampleCRL()
        const asn1 = crl.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3)

        // First element should be the tbsCertList (a Sequence)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)

        // Second element should be the signatureAlgorithm (a Sequence)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)

        // Third element should be the signature (a BitString)
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.BitString)
    })

    test('can be converted into ASN.1 and back', () => {
        const crl = createSampleCRL()
        const asn1 = crl.toAsn1()

        // Convert back to CRL
        const restoredCrl = CertificateList.fromAsn1(asn1)

        // Check that the basic structure is preserved
        expect(restoredCrl).toBeInstanceOf(CertificateList)
        expect(restoredCrl.signatureAlgorithm.algorithm).toEqual(
            crl.signatureAlgorithm.algorithm,
        )

        // Check that the signature value is preserved
        expect(restoredCrl.signatureValue).toEqual(crl.signatureValue)

        // Check that the TBSCertList is preserved
        expect(restoredCrl.tbsCertList.version).toEqual(crl.tbsCertList.version)
        expect(restoredCrl.tbsCertList.signature.algorithm).toEqual(
            crl.tbsCertList.signature.algorithm,
        )

        // Check that dates are preserved (using valueOf to compare only the time values)
        expect(restoredCrl.tbsCertList.thisUpdate.valueOf()).toEqual(
            crl.tbsCertList.thisUpdate.valueOf(),
        )
        expect(restoredCrl.tbsCertList.nextUpdate?.valueOf()).toEqual(
            crl.tbsCertList.nextUpdate?.valueOf(),
        )

        // Check that revoked certificates are preserved
        expect(restoredCrl.tbsCertList.revokedCertificates?.length).toEqual(
            crl.tbsCertList.revokedCertificates?.length,
        )
    })

    test('can be created with minimal fields', () => {
        // Create issuer name
        const createName = (): Name => {
            const cn = new AttributeTypeAndValue({
                type: '2.5.4.3',
                value: 'Test CA',
            })
            const cnRdn = new RelativeDistinguishedName()
            cnRdn.push(cn)

            const name = new Name.RDNSequence()
            name.push(cnRdn)

            return name
        }

        // Create minimal CRL information
        const tbsCertList = new TBSCertList({
            signature: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }), // SHA256 with RSA
            issuer: createName(),
            thisUpdate: new Date(),
        })

        // Create signature (just a placeholder for testing)
        const signatureValue = new Uint8Array([10, 20, 30, 40, 50])

        // Create the CRL
        const crl = new CertificateList({
            tbsCertList,
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }), // SHA256 with RSA
            signatureValue,
        })

        expect(crl).toBeInstanceOf(CertificateList)

        // Convert to ASN.1 and verify
        const asn1 = crl.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)

        // The tbsCertList should have 3 elements (signature, issuer, thisUpdate)
        const tbsAsn1 = asn1.valueBlock.value[0]
        assert(tbsAsn1 instanceof asn1js.Sequence)
        expect(tbsAsn1.valueBlock.value.length).toEqual(3)
    })

    test('CertificateList toString snapshot', () => {
        const obj = createSampleCRL()
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[CertificateList] SEQUENCE :
            SEQUENCE :
              INTEGER : 1
              SEQUENCE :
                OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
              SEQUENCE :
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.3
                    PrintableString : 'Test CA'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.10
                    PrintableString : 'Test Organization'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.6
                    PrintableString : 'US'
              UTCTime : 2025-01-01T00:00:00.000Z
              UTCTime : 2026-01-01T00:00:00.000Z
              SEQUENCE :
                SEQUENCE :
                  INTEGER : 12345
                  UTCTime : 2025-06-01T00:00:00.000Z
                  SEQUENCE :
                    SEQUENCE :
                      OBJECT IDENTIFIER : 2.5.29.21
                      OCTET STRING : 0a0101
                SEQUENCE :
                  INTEGER : 67890
                  UTCTime : 2025-07-15T00:00:00.000Z
              [0] :
                SEQUENCE :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.29.20
                    OCTET STRING : 0100
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
            BIT STRING : 0000101000010100000111100010100000110010"
        `)
    })

    test('CertificateList toPem snapshot', () => {
        const obj = createSampleCRL()
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN X509 CRL-----
          MIHNMIG1AgEBMAsGCSqGSIb3DQEBCzA7MRAwDgYDVQQDEwdUZXN0IENBMRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCVVMXDTI1MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFowOTAhAgIwORcNMjUwNjAxMDAwMDAwWjAMMAoGA1UdFQQDCgEBMBQCAwEJMhcNMjUwNzE1MDAwMDAwWqANMAswCQYDVR0UBAIBADALBgkqhkiG9w0BAQsDBgAKFB4oMg==
          -----END X509 CRL-----"
        `)
    })
})

/**
 * Creates a sample CRL for testing.
 */
function createSampleCRL(): CertificateList {
    // Create issuer name
    const createName = (): Name => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test CA',
        })
        const cnRdn = new RelativeDistinguishedName()
        cnRdn.push(cn)

        const o = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Test Organization',
        })
        const oRdn = new RelativeDistinguishedName()
        oRdn.push(o)

        const c = new AttributeTypeAndValue({ type: '2.5.4.6', value: 'US' })
        const cRdn = new RelativeDistinguishedName()
        cRdn.push(c)

        const name = new Name.RDNSequence()
        name.push(cnRdn, oRdn, cRdn)

        return name
    }

    // Create CRL entry extensions
    const reasonCodeExt = new Extension({
        extnID: '2.5.29.21', // ReasonCode
        critical: false,
        extnValue: CRLReason.keyCompromise,
    })

    // Create revoked certificates
    const revoked1 = new RevokedCertificate({
        userCertificate: 12345,
        revocationDate: new Date('2025-06-01'),
        crlEntryExtensions: [reasonCodeExt],
    })

    const revoked2 = new RevokedCertificate({
        userCertificate: 67890,
        revocationDate: new Date('2025-07-15'),
    })

    // Create CRL extensions
    const crlNumberExt = new Extension({
        extnID: '2.5.29.20', // CRLNumber
        critical: false,
        extnValue: new Uint8Array([1, 0]), // value 256
    })

    // Create CRL information
    const tbsCertList = new TBSCertList({
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256 with RSA
        issuer: createName(),
        thisUpdate: new Date('2025-01-01'),
        nextUpdate: new Date('2026-01-01'),
        revokedCertificates: [revoked1, revoked2],
        extensions: [crlNumberExt],
        version: 1, // v2
    })

    // Create signature (just a placeholder for testing)
    const signatureValue = new Uint8Array([10, 20, 30, 40, 50])

    // Create the CRL
    return new CertificateList({
        tbsCertList,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256 with RSA
        signatureValue,
    })
}

const pkitsDer = (name: string) =>
    Uint8Array.from(atob(pkitsFiles[name]), (c) => c.charCodeAt(0))

// real CRLs from NIST PKITS (see test-fixtures/pkits)
const crl = (name: string) => CertificateList.fromDer(pkitsDer(name))
const cert = (name: string) => Certificate.fromDer(pkitsDer(name))

describe('CertificateList checks', () => {
    test('verify: true for the CRL issuer, false for another certificate', async () => {
        const goodCrl = crl('GoodCACRL')
        expect(await goodCrl.verify(cert('GoodCACert'))).toBe(true)
        expect(await goodCrl.verify(cert('TrustAnchorRootCertificate'))).toBe(
            false,
        )
    })

    test('verify: false for an issuer whose key may not sign CRLs', async () => {
        const issuer = cert('keyUsageCriticalcRLSignFalseCACert')
        expect(issuer.allowsKeyUsage('cRLSign')).toBe(false)
        expect(
            await crl('keyUsageCriticalcRLSignFalseCACRL').verify(issuer),
        ).toBe(false)
    })

    test('verify: false for a CRL with a bad signature', async () => {
        expect(
            await crl('BadCRLSignatureCACRL').verify(
                cert('BadCRLSignatureCACert'),
            ),
        ).toBe(false)
    })

    test('isCurrent checks thisUpdate and nextUpdate', () => {
        const at = new Date('2026-01-01T00:00:00Z')
        expect(crl('GoodCACRL').isCurrent(at)).toBe(true)
        expect(
            crl('GoodCACRL').isCurrent(new Date('2000-01-01T00:00:00Z')),
        ).toBe(false)
        expect(crl('OldCRLnextUpdateCACRL').isCurrent(at)).toBe(false)
    })

    test('isRevoked / getRevokedEntry find the certificate on the CRL', () => {
        const goodCrl = crl('GoodCACRL')
        const revoked = cert('InvalidRevokedEETest3EE')
        expect(goodCrl.isRevoked(revoked)).toBe(true)
        expect(goodCrl.getRevokedEntry(revoked)?.reason).toBe(1) // keyCompromise
        expect(goodCrl.isRevoked(cert('ValidCertificatePathTest1EE'))).toBe(
            false,
        )
    })

    test("isRevoked uses an indirect CRL's certificateIssuer entries", () => {
        // indirect CRL from CA5 listing a certificate issued by CA6 (PKITS 4.14.31)
        const indirect = crl('indirectCRLCA5CRL')
        expect(indirect.issuingDistributionPoint?.indirectCRL).toBe(true)
        expect(indirect.isRevoked(cert('InvalidcRLIssuerTest31EE'))).toBe(true)
    })

    test('crlNumber, baseCrlNumber and isDelta', () => {
        const complete = crl('deltaCRLCA1CRL')
        const delta = crl('deltaCRLCA1deltaCRL')
        expect(complete.isDelta).toBe(false)
        expect(complete.crlNumber).toBeTypeOf('bigint')
        expect(delta.isDelta).toBe(true)
        expect(delta.baseCrlNumber).toBe(complete.crlNumber)
    })

    test('issuingDistributionPoint', () => {
        expect(
            crl('onlyContainsCACertsCACRL').issuingDistributionPoint
                ?.onlyContainsCACerts,
        ).toBe(true)
        expect(crl('GoodCACRL').issuingDistributionPoint).toBeUndefined()
    })
})
