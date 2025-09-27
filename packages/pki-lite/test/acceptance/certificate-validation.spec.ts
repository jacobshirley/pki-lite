import { describe, expect, test } from 'vitest'
import { KeyGen } from '../../src/core/KeyGen.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { Extension } from '../../src/x509/Extension.js'
import { CertificateValidationOptions } from '../../src/core/CertificateValidator.js'
import {
    AccessDescription,
    AuthorityInfoAccess,
} from '../../src/x509/extensions/AuthorityInfoAccess.js'
import { OIDs } from '../../src/core/OIDs.js'
import { GeneralName } from '../../src/x509/GeneralName.js'

describe('Certificate Validation', () => {
    test('Certificate chain validation', async () => {
        const rootCaKeys = await KeyGen.generate({
            algorithm: 'RSA',
            params: {
                hash: 'SHA-256',
                keySize: 4096,
            },
        })

        const rootCa = await Certificate.createSelfSigned({
            privateKeyInfo: rootCaKeys.privateKey,
            subjectPublicKeyInfo: rootCaKeys.publicKey,
            subject: 'C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA',
            validity: {
                notBefore: new Date('2025-01-01T00:00:00Z'),
                notAfter: new Date('2035-01-01T00:00:00Z'),
            },
            extensions: [
                Extension.basicConstraints({
                    cA: true,
                    pathLenConstraint: 1,
                }),
                Extension.keyUsage({
                    keyCertSign: true,
                    cRLSign: true,
                    digitalSignature: true,
                }),
            ],
        })

        const intermediateCaKeys = await KeyGen.generate({
            algorithm: 'RSA',
            params: {
                keySize: 4096,
                hash: 'SHA-256',
            },
        })

        const intermediateCa = await Certificate.createCertificate({
            privateKeyInfo: rootCaKeys.privateKey,
            subjectPublicKeyInfo: intermediateCaKeys.publicKey,
            issuer: rootCa,
            subject:
                'C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyIntermediateCA',
            validity: {
                notBefore: new Date('2025-01-01T00:00:00Z'),
                notAfter: new Date('2030-01-01T00:00:00Z'),
            },
            extensions: [
                Extension.basicConstraints({
                    cA: true,
                    pathLenConstraint: 0,
                }),
                Extension.keyUsage({
                    keyCertSign: true,
                    cRLSign: true,
                    digitalSignature: true,
                }),
            ],
        })

        const endEntityKeys = await KeyGen.generate({
            algorithm: 'RSA',
            params: {
                keySize: 2048,
                hash: 'SHA-256',
            },
        })

        const endEntityCert = await Certificate.createCertificate({
            privateKeyInfo: intermediateCaKeys.privateKey,
            subjectPublicKeyInfo: endEntityKeys.publicKey,
            issuer: intermediateCa,
            subject: 'C=US, ST=Test, L=Local, O=MyOrg, OU=Dev, CN=MyCodeSign',
            validity: {
                notBefore: new Date('2025-01-01T00:00:00Z'),
                notAfter: new Date('2026-01-01T00:00:00Z'),
            },
            extensions: [
                Extension.authorityInfoAccess(
                    new AuthorityInfoAccess(
                        new AccessDescription({
                            accessMethod: OIDs.AUTHORITY_INFO_ACCESS.CA_ISSUERS,
                            accessLocation:
                                new GeneralName.uniformResourceIdentifier({
                                    value: 'http://localhost:8080/ca.crt',
                                }),
                        }),
                    ),
                ),
                Extension.extendedKeyUsage({
                    codeSigning: true,
                }),
            ],
        })

        const validationOptions: CertificateValidationOptions = {
            trustAnchors: [
                {
                    certificate: rootCa,
                },
            ],
            validateNameConstraints: true,
            validateChain: true,
            checkSignature: true,
            enforceCAConstraints: true,
        }

        const fetch = globalThis.fetch
        globalThis.fetch = (url, init) => {
            if (url === 'http://localhost:8080/ca.crt') {
                return Promise.resolve(new Response(intermediateCa.toDer()))
            }
            return Promise.reject(new Error('Not Found: ' + url))
        }

        const result = await endEntityCert.validate(validationOptions)
        expect(result.isValid, result.messages.join(', ')).toBe(true)
        globalThis.fetch = fetch
    })
})
