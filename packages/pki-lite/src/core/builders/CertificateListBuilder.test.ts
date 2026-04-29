import { describe, it, expect } from 'vitest'
import { CertificateList } from '../../x509/CertificateList.js'
import { Certificate } from '../../x509/Certificate.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { KeyGen } from '../KeyGen.js'

describe('CertificateListBuilder', () => {
    it('builds an empty CRL and round-trips', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const crl = await CertificateList.builder()
            .setIssuerFromCertificate(cert)
            .setPrivateKey(privateKey)
            .setThisUpdate(new Date())
            .setNextUpdate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
            .build()

        expect(crl).toBeInstanceOf(CertificateList)
        expect(crl.tbsCertList.issuer.toString()).toEqual(
            cert.tbsCertificate.subject.toString(),
        )

        // Round-trip
        const der = crl.toDer()
        const decoded = CertificateList.fromDer(der)
        expect(decoded.toDer()).toEqual(crl.toDer())
    })

    it('builds a CRL with revoked certificates', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const crl = await CertificateList.builder()
            .setIssuerFromCertificate(cert)
            .setPrivateKey(privateKey)
            .setThisUpdate(new Date())
            .setNextUpdate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
            .addRevokedCertificate({
                serialNumber: 12345,
                revocationDate: new Date('2024-01-01T00:00:00Z'),
            })
            .addRevokedCertificate({
                serialNumber: 67890,
                revocationDate: new Date('2024-01-02T00:00:00Z'),
            })
            .build()

        expect(crl).toBeInstanceOf(CertificateList)
        expect(crl.tbsCertList.revokedCertificates).toBeDefined()
        expect(crl.tbsCertList.revokedCertificates!.length).toBe(2)
    })

    it('builds a CRL revoking a specific certificate', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const caPrivateKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )

        // Create a certificate to revoke
        const userKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const userCert = await Certificate.builder()
            .setSubject('CN=user@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(userKeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        // Build CRL that revokes this certificate
        const crl = await CertificateList.builder()
            .setIssuerFromCertificate(caCert)
            .setPrivateKey(caPrivateKey)
            .setThisUpdate(new Date())
            .setNextUpdate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
            .revokeCertificate(userCert)
            .build()

        expect(crl).toBeInstanceOf(CertificateList)
        expect(crl.tbsCertList.revokedCertificates).toBeDefined()
        expect(crl.tbsCertList.revokedCertificates!.length).toBe(1)

        const revokedSerial =
            crl.tbsCertList.revokedCertificates![0].userCertificate.toString()
        const userSerial = userCert.tbsCertificate.serialNumber.toString()
        expect(revokedSerial).toBe(userSerial)
    })

    it('builds a CRL with custom issuer name', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const crl = await CertificateList.builder()
            .setIssuer('CN=Custom CA, O=Example Org, C=US')
            .setPrivateKey(privateKey)
            .setThisUpdate(new Date('2024-01-01T00:00:00Z'))
            .setNextUpdate(new Date('2024-02-01T00:00:00Z'))
            .build()

        expect(crl).toBeInstanceOf(CertificateList)
        const issuerStr = crl.tbsCertList.issuer.toString()
        expect(issuerStr).toContain('Custom CA')
    })

    it('builds a CRL with default validity period', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const beforeBuild = Date.now()
        const crl = await CertificateList.builder()
            .setIssuerFromCertificate(cert)
            .setPrivateKey(privateKey)
            .build()
        const afterBuild = Date.now()

        expect(crl).toBeInstanceOf(CertificateList)
        expect(crl.tbsCertList.thisUpdate).toBeDefined()
        expect(crl.tbsCertList.nextUpdate).toBeDefined()

        // Verify thisUpdate is around now
        const thisUpdate = crl.tbsCertList.thisUpdate!.getTime()
        expect(thisUpdate).toBeGreaterThanOrEqual(beforeBuild - 1000)
        expect(thisUpdate).toBeLessThanOrEqual(afterBuild + 1000)

        // Verify nextUpdate is ~30 days after thisUpdate
        const nextUpdate = crl.tbsCertList.nextUpdate!.getTime()
        const thirtyDays = 30 * 24 * 60 * 60 * 1000
        expect(nextUpdate - thisUpdate).toBeCloseTo(thirtyDays, -5) // Within ~100s
    })
})
