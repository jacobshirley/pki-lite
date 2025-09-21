import { describe, it, expect, beforeEach, assert } from 'vitest'
import { SignedData } from './SignedData.js'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'
import { SignerInfo } from './SignerInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { DigestAlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { TBSCertList } from '../x509/TBSCertList.js'
import { Extension } from '../x509/Extension.js'
import { RevokedCertificate } from '../x509/RevokedCertificate.js'
import { CRLReason } from '../x509/CRLReason.js'

describe('SignedData', () => {
    let digestAlgorithms: DigestAlgorithmIdentifier[]
    let encapContentInfo: EncapsulatedContentInfo
    let signerInfos: SignerInfo[]

    beforeEach(() => {
        // Set up digest algorithms
        digestAlgorithms = [
            new DigestAlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.2.1',
            }), // SHA-256
        ]

        // Set up content info
        encapContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: new Uint8Array([1, 2, 3, 4]),
        })

        // Set up signer info
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )

        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: issuer,
            serialNumber: 12345,
        })
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const digestEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const encryptedDigest = new Uint8Array([5, 6, 7, 8, 9])

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm: digestAlgorithm,
            signatureAlgorithm: digestEncryptionAlgorithm,
            signature: encryptedDigest,
        })

        signerInfos = [signerInfo]
    })

    it('should create SignedData without certificates and CRLs', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
        })

        expect(signedData.version).toBe(1)
        expect(signedData.digestAlgorithms).toEqual(digestAlgorithms)
        expect(signedData.encapContentInfo).toEqual(encapContentInfo)
        expect(signedData.signerInfos).toEqual(signerInfos)
        expect(signedData.certificates).toBeUndefined()
        expect(signedData.crls).toBeUndefined()
    })

    it('should create SignedData with certificates and CRLs', () => {
        const certificates: Certificate[] = []
        const crls: CertificateList[] = [createSampleCRL()]

        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
            certificates: certificates,
            crls: crls,
        })

        expect(signedData.certificates).toEqual(undefined) // empty array treated as undefined
        expect(signedData.crls).toEqual(crls)
        expect(signedData.toString()).toMatchInlineSnapshot(`
          "[SignedData] SEQUENCE :
            INTEGER : 1
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              [0] :
                OCTET STRING : 01020304
            [1] :
              SEQUENCE :
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
                BIT STRING : 0000101000010100000111100010100000110010
            SET :
              SEQUENCE :
                INTEGER : 1
                SEQUENCE :
                  SEQUENCE :
                    SET :
                      SEQUENCE :
                        OBJECT IDENTIFIER : 2.5.4.3
                        PrintableString : 'Test CA'
                  INTEGER : 12345
                SEQUENCE :
                  OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                OCTET STRING : 0506070809"
        `)
    })

    it('should convert to ASN.1 structure without certificates and CRLs', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
        })

        const asn1 = signedData.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect((asn1 as any).valueBlock.value).toHaveLength(4) // version, digestAlgorithms, encapContentInfo, signerInfos
    })

    it('should convert to string', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
        })

        const str = signedData.toString()

        expect(typeof str).toBe('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('should parse from ASN.1 structure', () => {
        // First create a SignedData instance and convert to ASN.1
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
        })

        const asn1 = signedData.toAsn1()

        // Then parse it back
        const parsedSignedData = SignedData.fromAsn1(asn1)

        // Verify the basic structure (partial verification due to simplified implementation)
        expect(parsedSignedData.version).toBe(1)
        expect(parsedSignedData.digestAlgorithms.length).toBe(1)
        // Use partial matching to check just the algorithm string
        expect(parsedSignedData.digestAlgorithms[0].algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.1',
        )
        expect(parsedSignedData.encapContentInfo.eContentType.toString()).toBe(
            OIDs.PKCS7.DATA,
        )
        // The other properties are placeholders in our current implementation
    })

    it('SignedData toString snapshot', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
        })
        expect(signedData.toString()).toMatchInlineSnapshot(`
          "[SignedData] SEQUENCE :
            INTEGER : 1
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              [0] :
                OCTET STRING : 01020304
            SET :
              SEQUENCE :
                INTEGER : 1
                SEQUENCE :
                  SEQUENCE :
                    SET :
                      SEQUENCE :
                        OBJECT IDENTIFIER : 2.5.4.3
                        PrintableString : 'Test CA'
                  INTEGER : 12345
                SEQUENCE :
                  OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                OCTET STRING : 0506070809"
        `)
    })

    it('SignedData toString snapshot with certificates and CRLs', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
            certificates: [], // certificates
            crls: [], // crls
        })
        expect(signedData.toString()).toMatchInlineSnapshot(`
          "[SignedData] SEQUENCE :
            INTEGER : 1
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              [0] :
                OCTET STRING : 01020304
            SET :
              SEQUENCE :
                INTEGER : 1
                SEQUENCE :
                  SEQUENCE :
                    SET :
                      SEQUENCE :
                        OBJECT IDENTIFIER : 2.5.4.3
                        PrintableString : 'Test CA'
                  INTEGER : 12345
                SEQUENCE :
                  OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                OCTET STRING : 0506070809"
        `)
    })

    it('SignedData toPem snapshot', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
        })
        expect(signedData.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN SIGNEDDATA-----
          MGkCAQExDTALBglghkgBZQMEAgEwEwYJKoZIhvcNAQcBoAYEBAECAwQxQDA+AgEBMBgwEjEQMA4GA1UEAxMHVGVzdCBDQQICMDkwCwYJYIZIAWUDBAIBMAsGCSqGSIb3DQEBAQQFBQYHCAk=
          -----END SIGNEDDATA-----"
        `)
    })

    it('SignedData toPem snapshot with certificates and CRLs', () => {
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContentInfo,
            signerInfos: signerInfos,
            certificates: [], // certificates
            crls: [], // crls
        })
        expect(signedData.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN SIGNEDDATA-----
          MGkCAQExDTALBglghkgBZQMEAgEwEwYJKoZIhvcNAQcBoAYEBAECAwQxQDA+AgEBMBgwEjEQMA4GA1UEAxMHVGVzdCBDQQICMDkwCwYJYIZIAWUDBAIBMAsGCSqGSIb3DQEBAQQFBQYHCAk=
          -----END SIGNEDDATA-----"
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
