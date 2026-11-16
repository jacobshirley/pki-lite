import { assert, describe, expect, test } from 'vitest'
import { Certificate } from './Certificate.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Validity } from './Validity.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from './Name.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'
import { pkitsFiles } from '../../test-fixtures/pkits/pkits.js'
import { GeneralName } from './GeneralName.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'

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

    // Regression test for issue #84: OpenSSL uses implicit tagging for SAN entries
    test('getSubjectAltNames parses OpenSSL-generated certificate with implicit-tagged dNSName', () => {
        const certPem = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUcrK/GL//nD5tolE0vt6Vy5EEj9YwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYwMzMxMjAwNzM5WhcNMjcw
MzMxMjAwNzM5WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALZKfc0D7gVZUn88yH9dNgseviWi55W6ZVy7Doha
eTVC4e0qDtJycW8KVYNoc2MmJN3pnQpc5P7tFJ9I5/zaVQ3WqMVDI8lesDlwoUmI
iFizxBxotmQOGo/G1ZU3wAGtzogs6MPZ5m10fPom7gRifT4rvl24GMXxoGZQlstE
QSW4nrT/X5e2nzDn+qUeRTwg30u5X3j4ojLFf3IQeQuXgjNpwi1u661iXMDgDT2G
mI9IYVoK9rAT00OUuMm024o+irA1XXDtY594jKS4QsSGHN7BCKLCM+8mw7G0oDqQ
VNdVr8Q/SZoiL7b3+Tjo8JIPWoPsNHCMBysYHnfmdBuO5kcCAwEAAaNrMGkwHQYD
VR0OBBYEFIKs2ZBlbwHlfokChUyYQrNk5GpAMB8GA1UdIwQYMBaAFIKs2ZBlbwHl
fokChUyYQrNk5GpAMA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0RBA8wDYILZXhhbXBs
ZS5jb20wDQYJKoZIhvcNAQELBQADggEBAHDCvJwp9HkLMUUNzn0pNXP7YgxDDzjJ
HTgVHdwcyz1v0u+1jJXmuWy0T6Oq79NAMIol37NinsMoH3/UNLbZc+NJ23PplHy9
sSvpifUgAW2/JgBnQddas8IYusBdckqE2RJD2XdNHsNpyMX9SrC6PawEDT28xVx9
gp89l0naLH02o+NguQYJv+taCGp96o9VEEhap/qUcSQI+C6RMcWth2EHAXmLaYxp
PdX78veNZQefzueZK3mlv41LkAIYlEHgH9/p31EbDZmbZcpbPDDMOY9Xbpcu4iha
YCq9EV5g9cM3mH/4raahln+1O63McYb36rlLFrJaQz+aX7A/9Wir1Jk=
-----END CERTIFICATE-----`

        const cert = Certificate.fromPem(certPem)

        const sans = cert.getSubjectAltNames()
        expect(sans).toHaveLength(1)
        expect(sans[0]).toHaveLength(1)
        expect(sans[0][0].toString()).toEqual('example.com')

        expect(cert.getCommonName()).toEqual('example.com')
    })
})

const pkitsDer = (name: string) =>
    Uint8Array.from(atob(pkitsFiles[name]), (c) => c.charCodeAt(0))

describe('Certificate extension helpers', () => {
    const cert = (name: string) => Certificate.fromDer(pkitsDer(name))

    test('isCA', () => {
        expect(cert('GoodCACert').isCA()).toBe(true)
        expect(cert('ValidCertificatePathTest1EE').isCA()).toBe(false)
    })

    test('allowsKeyUsage', () => {
        const ca = cert('keyUsageCriticalcRLSignFalseCACert')
        expect(ca.allowsKeyUsage('keyCertSign')).toBe(true)
        expect(ca.allowsKeyUsage('cRLSign')).toBe(false)
    })

    test('getCrlDistributionPoints', () => {
        const points = cert(
            'InvalidcRLIssuerTest31EE',
        ).getCrlDistributionPoints()
        expect(points).toHaveLength(1)
        expect(points[0].cRLIssuer).toBeDefined()
        expect(
            cert('ValidCertificatePathTest1EE').getCrlDistributionPoints(),
        ).toEqual([])
    })
})

describe('Certificate.matchesHostname (RFC 9525)', () => {
    const withNames = (...names: GeneralName[]) => {
        const builder = Certificate.builder()
            .setSubject('CN=not.used.example')
            .setPublicKey(
                Certificate.fromPem(rsaSigningKeys.certPem).tbsCertificate
                    .subjectPublicKeyInfo,
            )
            .setPrivateKey(PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem))
            .setValidityDays(1)
        if (names.length > 0) builder.addSubjectAltName(...names)
        return builder.selfSign()
    }
    const dns = (value: string) => new GeneralName.dNSName({ value })
    const ip = (value: string) => GeneralName.iPAddress.fromString(value)

    test('DNS names: exact, ignoring case and a trailing dot', async () => {
        const cert = await withNames(dns('www.example.com'))
        expect(cert.matchesHostname('www.example.com')).toBe(true)
        expect(cert.matchesHostname('WWW.Example.COM.')).toBe(true)
        expect(cert.matchesHostname('example.com')).toBe(false)
        expect(cert.matchesHostname('a.www.example.com')).toBe(false)
    })

    test('wildcards match one whole leftmost label', async () => {
        const cert = await withNames(dns('*.example.com'))
        expect(cert.matchesHostname('www.example.com')).toBe(true)
        expect(cert.matchesHostname('example.com')).toBe(false)
        expect(cert.matchesHostname('a.b.example.com')).toBe(false)
        for (const pattern of ['*.com', '*', 'w*.example.com', 'www.*.com']) {
            expect(
                (await withNames(dns(pattern))).matchesHostname(
                    'www.example.com',
                ),
                pattern,
            ).toBe(false)
        }
    })

    test('internationalised names compare as A-labels', async () => {
        const cert = await withNames(dns('xn--bcher-kva.example'))
        expect(cert.matchesHostname('bücher.example')).toBe(true)
        expect(cert.matchesHostname('xn--bcher-kva.example')).toBe(true)
        // a dNSName must be ASCII: a U-label in the certificate matches nothing
        expect(
            (await withNames(dns('bücher.example'))).matchesHostname(
                'bücher.example',
            ),
        ).toBe(false)
    })

    test('IP addresses match iPAddress names only', async () => {
        const cert = await withNames(
            ip('192.0.2.1'),
            ip('2001:db8::1'),
            dns('192.0.2.9'),
        )
        expect(cert.matchesHostname('192.0.2.1')).toBe(true)
        expect(cert.matchesHostname('2001:DB8:0::1')).toBe(true)
        expect(cert.matchesHostname('[2001:db8::1]')).toBe(true)
        // an IP address in a dNSName does not count
        expect(cert.matchesHostname('192.0.2.9')).toBe(false)
    })

    test('the common name is not used', async () => {
        const cert = await withNames()
        expect(cert.matchesHostname('not.used.example')).toBe(false)
    })
})

describe('Certificate.allowsExtendedKeyUsage (RFC 5280 4.2.1.12)', () => {
    const withEku = (eku?: Record<string, boolean>) => {
        const builder = Certificate.builder()
            .setSubject('CN=EKU')
            .setPublicKey(
                Certificate.fromPem(rsaSigningKeys.certPem).tbsCertificate
                    .subjectPublicKeyInfo,
            )
            .setPrivateKey(PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem))
            .setValidityDays(1)
        if (eku) builder.addExtendedKeyUsage(eku)
        return builder.selfSign()
    }

    test('no extendedKeyUsage extension places no limit', async () => {
        expect((await withEku()).allowsExtendedKeyUsage('serverAuth')).toBe(
            true,
        )
    })

    test('the listed purposes only, by name or OID', async () => {
        const cert = await withEku({ clientAuth: true })
        expect(cert.allowsExtendedKeyUsage('clientAuth')).toBe(true)
        expect(cert.allowsExtendedKeyUsage('1.3.6.1.5.5.7.3.2')).toBe(true)
        expect(cert.allowsExtendedKeyUsage('serverAuth')).toBe(false)
    })

    test('anyExtendedKeyUsage allows every purpose', async () => {
        const cert = await withEku({ '2.5.29.37.0': true })
        expect(cert.allowsExtendedKeyUsage('codeSigning')).toBe(true)
    })
})
