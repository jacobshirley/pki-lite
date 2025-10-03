import { assert, describe, expect, test } from 'vitest'
import { Certificate } from './Certificate.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Validity } from './Validity.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from './Name.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'

/**
 * Creates a sample certificate for testing.
 */
function createSampleCertificate(): Certificate {
    // Create subject and issuer names
    const createName = (): Name => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Certificate',
        })
        const cnRdn: RelativeDistinguishedName = new RelativeDistinguishedName()
        cnRdn.push(cn)

        const o = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Test Organization',
        })
        const oRdn: RelativeDistinguishedName = new RelativeDistinguishedName()
        oRdn.push(o)

        const c = new AttributeTypeAndValue({ type: '2.5.4.6', value: 'US' })
        const cRdn: RelativeDistinguishedName = new RelativeDistinguishedName()
        cRdn.push(c)

        const name = new Name.RDNSequence()
        name.push(cnRdn, oRdn, cRdn)

        return name
    }

    // Create a sample key (just a placeholder for testing)
    const publicKey = new Uint8Array([1, 2, 3, 4, 5])

    // Create subject key info
    const spki = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    // Create validity period
    const validity = new Validity({
        notBefore: new Date('2025-01-01'),
        notAfter: new Date('2026-01-01'),
    })

    // Create certificate information
    const tbsCertificate = new Certificate.TBSCertificate({
        issuer: createName(),
        subject: createName(),
        subjectPublicKeyInfo: spki,
        serialNumber: new Uint8Array([0x49, 0x96, 0x02, 0xd2]), // 1234567890
        validity,
        version: 2, // v3
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256 with RSA
    })

    // Create signature (just a placeholder for testing)
    const signatureValue = new Uint8Array([10, 20, 30, 40, 50])

    // Create the certificate
    return new Certificate({
        tbsCertificate,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue,
    })
}

describe('Certificate', () => {
    test('can be created', () => {
        const certificate = createSampleCertificate()
        expect(certificate).toBeInstanceOf(Certificate)
    })

    test('can be converted into ASN.1', () => {
        const cert = createSampleCertificate()
        const asn1 = cert.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3)

        // First element should be the tbsCertificate (a Sequence)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)

        // Second element should be the signatureAlgorithm (a Sequence)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)

        // Third element should be the signatureValue (a BitString)
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.BitString)
    })

    test('can be converted into ASN.1 and back', async () => {
        const cert = createSampleCertificate()
        const asn1 = cert.toAsn1()
        const restoredCert = Certificate.fromAsn1(asn1)

        expect(restoredCert).toEqual(cert)
    })

    test('Certificate toString snapshot', () => {
        const certificate = createSampleCertificate()
        expect(certificate.toString()).toMatchInlineSnapshot(`
          "[Certificate] SEQUENCE :
            SEQUENCE :
              [0] :
                INTEGER : 2
              INTEGER : 1234567890
              SEQUENCE :
                OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
              SEQUENCE :
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.3
                    PrintableString : 'Test Certificate'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.10
                    PrintableString : 'Test Organization'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.6
                    PrintableString : 'US'
              SEQUENCE :
                UTCTime : 2025-01-01T00:00:00.000Z
                UTCTime : 2026-01-01T00:00:00.000Z
              SEQUENCE :
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.3
                    PrintableString : 'Test Certificate'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.10
                    PrintableString : 'Test Organization'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.6
                    PrintableString : 'US'
              SEQUENCE :
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                BIT STRING : 0000000100000010000000110000010000000101
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
            BIT STRING : 0000101000010100000111100010100000110010"
        `)
    })

    test('Certificate toPem snapshot', () => {
        const certificate = createSampleCertificate()
        expect(certificate.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN CERTIFICATE-----
          MIHzMIHboAMCAQICBEmWAtIwCwYJKoZIhvcNAQELMEQxGTAXBgNVBAMTEFRlc3QgQ2VydGlmaWNhdGUxGjAYBgNVBAoTEVRlc3QgT3JnYW5pemF0aW9uMQswCQYDVQQGEwJVUzAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMEQxGTAXBgNVBAMTEFRlc3QgQ2VydGlmaWNhdGUxGjAYBgNVBAoTEVRlc3QgT3JnYW5pemF0aW9uMQswCQYDVQQGEwJVUzAVMAsGCSqGSIb3DQEBAQMGAAECAwQFMAsGCSqGSIb3DQEBCwMGAAoUHigy
          -----END CERTIFICATE-----"
        `)
    })
})
