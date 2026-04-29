import { describe, it, expect } from 'vitest'
import { PFX } from '../../pkcs12/PFX.js'
import { Certificate } from '../../x509/Certificate.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('PFXBuilder', () => {
    it('builds a PFX containing certificate + private key and round-trips', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const pfx = await PFX.builder()
            .addCertificate(cert)
            .addPrivateKey(privateKey)
            .setPassword('test-password')
            .setIterations(1024)
            .build()

        expect(pfx).toBeInstanceOf(PFX)
        expect(pfx.macData).toBeDefined()

        // Round-trip
        const der = pfx.toDer()
        const decoded = PFX.fromDer(der)

        const certs = await decoded.getX509Certificates('test-password')
        const keys = await decoded.getPrivateKeys('test-password')

        expect(certs).toHaveLength(1)
        expect(keys).toHaveLength(1)
        expect(certs[0].toDer()).toEqual(cert.toDer())
        expect(keys[0].toDer()).toEqual(privateKey.toDer())
    })

    it('builds a PFX with friendlyName', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const pfx = await PFX.builder()
            .addCertificate(cert)
            .addPrivateKey(privateKey)
            .setPassword('pw')
            .setFriendlyName('My Identity')
            .build()

        const der = pfx.toDer()
        const decoded = PFX.fromDer(der)
        const items = await decoded.extractItems('pw')
        expect(items.certificates).toHaveLength(1)
        expect(items.privateKeys).toHaveLength(1)
    })

    it('PFX.create delegates to the builder', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        const pfx = await PFX.create({
            certificates: [cert],
            privateKeys: [privateKey],
            password: 'pw',
        })

        const decoded = PFX.fromDer(pfx.toDer())
        const items = await decoded.extractItems('pw')
        expect(items.certificates).toHaveLength(1)
        expect(items.privateKeys).toHaveLength(1)
    })

    it('throws when password is missing', async () => {
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        await expect(
            PFX.builder().addCertificate(cert).build(),
        ).rejects.toThrow(/password/i)
    })

    it('throws when no certs or keys are provided', async () => {
        await expect(PFX.builder().setPassword('pw').build()).rejects.toThrow(
            /at least one certificate/i,
        )
    })
})
