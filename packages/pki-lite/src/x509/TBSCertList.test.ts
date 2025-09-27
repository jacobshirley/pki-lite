import { assert, describe, expect, test } from 'vitest'
import { TBSCertList } from './TBSCertList.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from './Name.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { RevokedCertificate } from './RevokedCertificate.js'
import { Extension } from './Extension.js'
import { asn1js } from '../core/PkiBase.js'
import { CRLReason } from './CRLReason.js'

describe('TBSCertList', () => {
    test('can be created with minimal fields', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01')

        const tbsCertList = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
        })

        expect(tbsCertList).toBeInstanceOf(TBSCertList)
        expect(tbsCertList.signature).toBe(algorithm)
        expect(tbsCertList.issuer).toBe(issuer)
        expect(tbsCertList.thisUpdate).toBe(thisUpdate)
        expect(tbsCertList.version).toBeUndefined()
        expect(tbsCertList.nextUpdate).toBeUndefined()
        expect(tbsCertList.revokedCertificates).toBeUndefined()
        expect(tbsCertList.extensions).toBeUndefined()
    })

    test('can be created with all fields', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01')
        const nextUpdate = new Date('2026-01-01')

        // Create a revoked certificate
        const revoked = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2025-06-01'),
            crlEntryExtensions: [
                new Extension({
                    extnID: '2.5.29.21',
                    critical: false,
                    extnValue: CRLReason.keyCompromise, // Asn1 encoding of ENUMERATED { keyCompromise (1) }
                }),
            ], // reasonCode = keyCompromise
        })

        // Create an extension
        const crlExt = new Extension({
            extnID: '2.5.29.20',
            critical: false,
            extnValue: new Uint8Array([1, 0]),
        }) // CRLNumber = 256

        const tbsCertList = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates: [revoked],
            extensions: [crlExt],
            version: 1, // version v2
        })

        expect(tbsCertList).toBeInstanceOf(TBSCertList)
        expect(tbsCertList.signature).toBe(algorithm)
        expect(tbsCertList.issuer).toBe(issuer)
        expect(tbsCertList.thisUpdate).toBe(thisUpdate)
        expect(tbsCertList.nextUpdate).toBe(nextUpdate)
        expect(tbsCertList.revokedCertificates).toHaveLength(1)
        expect(tbsCertList.revokedCertificates?.[0]).toBe(revoked)
        expect(tbsCertList.extensions).toHaveLength(1)
        expect(tbsCertList.extensions?.[0]).toBe(crlExt)
        expect(tbsCertList.version).toBe(1)
    })

    test('can be converted to ASN.1 with minimal fields', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01')

        const tbsCertList = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
        })
        const asn1 = tbsCertList.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3) // signature, issuer, thisUpdate
    })

    test('can be converted to ASN.1 with all fields', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01')
        const nextUpdate = new Date('2026-01-01')

        // Create a revoked certificate
        const revoked = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2025-06-01'),
            crlEntryExtensions: [
                new Extension({
                    extnID: '2.5.29.21',
                    critical: false,
                    extnValue: CRLReason.keyCompromise, // Asn1 encoding of ENUMERATED { keyCompromise (1) }
                }),
            ], // reasonCode = keyCompromise
        })

        // Create an extension
        const crlExt = new Extension({
            extnID: '2.5.29.20',
            critical: false,
            extnValue: new Uint8Array([1, 0]),
        }) // CRLNumber = 256

        const tbsCertList = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates: [revoked],
            extensions: [crlExt],
            version: 1, // version v2
        })

        const asn1 = tbsCertList.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(7) // version, signature, issuer, thisUpdate, nextUpdate, revokedCerts, extensions

        // First element should be the version
        const versionBlock = asn1.valueBlock.value[0]
        expect(versionBlock).toBeInstanceOf(asn1js.Integer)

        // Last element should be the extensions with tagClass 3 (CONTEXT-SPECIFIC)
        const extensionsBlock = asn1.valueBlock.value[6]
        expect(extensionsBlock).toBeInstanceOf(asn1js.Constructed)
        expect((extensionsBlock as asn1js.Constructed).idBlock.tagClass).toBe(3)
        expect((extensionsBlock as asn1js.Constructed).idBlock.tagNumber).toBe(
            0,
        ) // [0]
    })

    test('can be converted to ASN.1 and back', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01')
        const nextUpdate = new Date('2026-01-01')

        // Create a revoked certificate
        const revoked = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2025-06-01'),
            crlEntryExtensions: [
                new Extension({
                    extnID: '2.5.29.21',
                    critical: false,
                    extnValue: CRLReason.keyCompromise, // Asn1 encoding of ENUMERATED { keyCompromise (1) }
                }),
            ], // reasonCode = keyCompromise
        })

        // Create an extension
        const crlExt = new Extension({
            extnID: '2.5.29.20',
            critical: false,
            extnValue: new Uint8Array([1, 0]),
        }) // CRLNumber = 256

        const tbsCertList = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates: [revoked],
            extensions: [crlExt],
            version: 1, // version v2
        })

        const asn1 = tbsCertList.toAsn1()

        // Convert back to TBSCertList
        const restoredTbs = TBSCertList.fromAsn1(asn1)

        // Check that the basic structure is preserved
        expect(restoredTbs).toBeInstanceOf(TBSCertList)
        expect(restoredTbs.version).toBe(tbsCertList.version)
        expect(restoredTbs.signature.algorithm.toString()).toBe(
            tbsCertList.signature.algorithm.toString(),
        )

        // Check that dates are preserved (using valueOf to compare only the time values)
        expect(restoredTbs.thisUpdate.valueOf()).toBe(
            tbsCertList.thisUpdate.valueOf(),
        )
        expect(restoredTbs.nextUpdate?.valueOf()).toBe(
            tbsCertList.nextUpdate?.valueOf(),
        )

        // Check that revoked certificates are preserved
        expect(restoredTbs.revokedCertificates?.length).toBe(
            tbsCertList.revokedCertificates?.length,
        )

        // Check that extensions are preserved
        expect(restoredTbs.extensions?.length).toBe(
            tbsCertList.extensions?.length,
        )
    })

    test('TBSCertList toString snapshot', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01T00:00:00.000Z')
        const nextUpdate = new Date('2026-01-01T00:00:00.000Z')
        const obj = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[TBSCertList] SEQUENCE :
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
            UTCTime : 2025-01-01T00:00:00.000Z
            UTCTime : 2026-01-01T00:00:00.000Z"
        `)
    })

    test('TBSCertList toString snapshot with revoked certificates', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01T00:00:00.000Z')
        const nextUpdate = new Date('2026-01-01T00:00:00.000Z')
        const revoked = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2025-06-01T00:00:00.000Z'),
        })
        const obj = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates: [revoked],
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[TBSCertList] SEQUENCE :
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
            UTCTime : 2025-01-01T00:00:00.000Z
            UTCTime : 2026-01-01T00:00:00.000Z
            SEQUENCE :
              SEQUENCE :
                INTEGER : 12345
                UTCTime : 2025-06-01T00:00:00.000Z"
        `)
    })

    test('TBSCertList toPem snapshot', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01T00:00:00.000Z')
        const nextUpdate = new Date('2026-01-01T00:00:00.000Z')
        const obj = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN TBSCERTLIST-----
          MFswCwYJKoZIhvcNAQELMC4xEDAOBgNVBAMTB1Rlc3QgQ0ExGjAYBgNVBAoTEVRlc3QgT3JnYW5pemF0aW9uFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBa
          -----END TBSCERTLIST-----"
        `)
    })

    test('TBSCertList toPem snapshot with revoked certificates and extensions', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const issuer = createSampleName()
        const thisUpdate = new Date('2025-01-01T00:00:00.000Z')
        const nextUpdate = new Date('2026-01-01T00:00:00.000Z')
        const revoked = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2025-06-01T00:00:00.000Z'),
        })
        const crlExt = new Extension({
            extnID: '2.5.29.20',
            critical: false,
            extnValue: new Uint8Array([1, 0]),
        })
        const obj = new TBSCertList({
            signature: algorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates: [revoked],
            extensions: [crlExt],
            version: 1,
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN TBSCERTLIST-----
          MIGEAgEBMAsGCSqGSIb3DQEBCzAuMRAwDgYDVQQDEwdUZXN0IENBMRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAxMDAwMDAwWjAVMBMCAjA5Fw0yNTA2MDEwMDAwMDBaoA0wCzAJBgNVHRQEAgEA
          -----END TBSCERTLIST-----"
        `)
    })
})

/**
 * Creates a sample name for testing.
 */
function createSampleName(): Name {
    const cn = new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Test CA' })
    const cnRdn = new RelativeDistinguishedName()
    cnRdn.push(cn)

    const o = new AttributeTypeAndValue({
        type: '2.5.4.10',
        value: 'Test Organization',
    })
    const oRdn = new RelativeDistinguishedName()
    oRdn.push(o)

    const name = new Name.RDNSequence()
    name.push(cnRdn, oRdn)

    return name
}
