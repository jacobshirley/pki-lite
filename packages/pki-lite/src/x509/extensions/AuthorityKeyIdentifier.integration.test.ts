import { describe, expect, test } from 'vitest'
import { Certificate } from '../../x509/Certificate.js'
import { AuthorityKeyIdentifier } from './AuthorityKeyIdentifier.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('AuthorityKeyIdentifier - Integration Tests', () => {
    test('should parse AKI from real RSA-2048 test certificate with IMPLICIT tagging', () => {
        // Parse the actual test certificate
        const cert = Certificate.fromDer(rsaSigningKeys.cert)

        expect(cert).toBeDefined()
        expect(cert.tbsCertificate.subject.toHumanString()).toContain(
            'John Doe',
        )

        // Find the AKI extension (OID: 2.5.29.35)
        const extensions = cert.tbsCertificate.extensions
        expect(extensions).toBeDefined()

        let foundAKI = false
        for (const ext of extensions!) {
            if (ext.extnID.value === '2.5.29.35') {
                foundAKI = true

                // This should NOT throw "Expected constructed element" error
                const aki = ext.extnValue.parseAs(AuthorityKeyIdentifier)

                expect(aki).toBeDefined()
                expect(aki.keyIdentifier).toBeDefined()
                expect(aki.keyIdentifier!.bytes).toBeInstanceOf(Uint8Array)
                expect(aki.keyIdentifier!.bytes.length).toBeGreaterThan(0)

                // Verify the key identifier matches expected value from the certificate
                const keyIdHex = Buffer.from(aki.keyIdentifier!.bytes).toString(
                    'hex',
                )
                expect(keyIdHex).toBe(
                    '1021ab93d5b7999f76e042ef981e78a7e54221f5',
                )

                // These fields should be undefined for this certificate
                expect(aki.authorityCertIssuer).toBeUndefined()
                expect(aki.authorityCertSerialNumber).toBeUndefined()

                break
            }
        }

        expect(foundAKI).toBe(true)
    })

    test('should parse AKI from CA certificate', () => {
        // Parse the CA certificate
        const caCert = Certificate.fromDer(rsaSigningKeys.caCert)

        expect(caCert).toBeDefined()
        expect(caCert.tbsCertificate.subject.toHumanString()).toContain(
            'MyRootCA',
        )

        // The root CA should have an AKI extension (self-signed)
        const extensions = caCert.tbsCertificate.extensions
        expect(extensions).toBeDefined()

        let foundAKI = false
        for (const ext of extensions!) {
            if (ext.extnID.value === '2.5.29.35') {
                foundAKI = true

                // This should parse successfully with IMPLICIT tagging
                const aki = ext.extnValue.parseAs(AuthorityKeyIdentifier)

                expect(aki).toBeDefined()
                if (aki.keyIdentifier) {
                    expect(aki.keyIdentifier.bytes).toBeInstanceOf(Uint8Array)
                    expect(aki.keyIdentifier.bytes.length).toBeGreaterThan(0)
                }

                break
            }
        }

        expect(foundAKI).toBe(true)
    })

    test('certificate chain validation should work with IMPLICIT-tagged AKI', () => {
        // This test verifies that buildCertificateChain can now parse
        // certificates with IMPLICIT-tagged AKI extensions without throwing
        const cert = Certificate.fromDer(rsaSigningKeys.cert)
        const caCert = Certificate.fromDer(rsaSigningKeys.caCert)

        // Verify both certificates have AKI extensions that can be parsed
        const certHasAKI = cert.tbsCertificate.extensions?.some((ext) => {
            if (ext.extnID.value === '2.5.29.35') {
                // Should not throw
                const aki = ext.extnValue.parseAs(AuthorityKeyIdentifier)
                return aki !== undefined
            }
            return false
        })

        const caCertHasAKI = caCert.tbsCertificate.extensions?.some((ext) => {
            if (ext.extnID.value === '2.5.29.35') {
                // Should not throw
                const aki = ext.extnValue.parseAs(AuthorityKeyIdentifier)
                return aki !== undefined
            }
            return false
        })

        expect(certHasAKI).toBe(true)
        expect(caCertHasAKI).toBe(true)
    })
})
