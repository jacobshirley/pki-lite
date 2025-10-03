import { assert, describe, expect, test } from 'vitest'
import { Certificate } from './Certificate.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Validity } from './Validity.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from './Name.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'
import { Extension } from './Extension.js'
import { KeyUsage } from './extensions/KeyUsage.js'
import { BasicConstraints } from './extensions/BasicConstraints.js'

/**
 * Creates a sample name for testing.
 */
function createSampleName(): Name {
    const cn = new AttributeTypeAndValue({
        type: '2.5.4.3',
        value: 'Test Certificate',
    })
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

describe('TBSCertificate', () => {
    test('can be created with required fields', () => {
        const version = 2 // X.509v3
        const serialNumber = 1234567890
        const signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })
        const subject = createSampleName()
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })

        const tbsCert = new Certificate.TBSCertificate({
            version: version,
            serialNumber: serialNumber,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
        })

        expect(tbsCert).toBeInstanceOf(Certificate.TBSCertificate)
        expect(tbsCert.version).toEqual(version)
        expect(tbsCert.serialNumber.toNumber()).toEqual(serialNumber)
        expect(tbsCert.signature).toEqual(signature)
        expect(tbsCert.issuer).toEqual(issuer)
        expect(tbsCert.validity).toEqual(validity)
        expect(tbsCert.subject).toEqual(subject)
        expect(tbsCert.subjectPublicKeyInfo).toEqual(spki)
        expect(tbsCert.issuerUniqueID).toBeUndefined()
        expect(tbsCert.subjectUniqueID).toBeUndefined()
        expect(tbsCert.extensions).toBeUndefined()
    })

    test('can be created with all fields', () => {
        const version = 2 // X.509v3
        const serialNumber = 1234567890
        const signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })
        const subject = createSampleName()
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })
        const issuerUniqueID = new Uint8Array([10, 11, 12])
        const subjectUniqueID = new Uint8Array([13, 14, 15])

        // Create extensions
        const keyUsageExt = new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: new KeyUsage({
                digitalSignature: true,
                keyEncipherment: true,
            }),
        }) // keyUsage
        const basicConstraintsExt = new Extension({
            extnID: '2.5.29.19',
            critical: true,
            extnValue: new BasicConstraints({
                cA: true,
            }),
        }) // basicConstraints

        const tbsCert = new Certificate.TBSCertificate({
            version: version,
            serialNumber: serialNumber,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
            issuerUniqueID: issuerUniqueID,
            subjectUniqueID: subjectUniqueID,
            extensions: [keyUsageExt, basicConstraintsExt],
        })

        expect(tbsCert).toBeInstanceOf(Certificate.TBSCertificate)
        expect(tbsCert.version).toEqual(version)
        expect(tbsCert.serialNumber.toInteger()).toEqual(serialNumber)
        expect(tbsCert.signature).toEqual(signature)
        expect(tbsCert.issuer).toEqual(issuer)
        expect(tbsCert.validity).toEqual(validity)
        expect(tbsCert.subject).toEqual(subject)
        expect(tbsCert.subjectPublicKeyInfo).toEqual(spki)
        expect(tbsCert.issuerUniqueID).toEqual(issuerUniqueID)
        expect(tbsCert.subjectUniqueID).toEqual(subjectUniqueID)
        expect(tbsCert.extensions).toHaveLength(2)
        expect(tbsCert.extensions?.[0]).toEqual(keyUsageExt)
        expect(tbsCert.extensions?.[1]).toEqual(basicConstraintsExt)
    })

    test('can be created with string serial number', () => {
        const version = 2 // X.509v3
        const serialNumber = '1234567890'
        const signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })
        const subject = createSampleName()
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })

        const tbsCert = new Certificate.TBSCertificate({
            version: version,
            serialNumber: serialNumber,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
        })

        expect(tbsCert).toBeInstanceOf(Certificate.TBSCertificate)
        expect(tbsCert.serialNumber.toString()).toEqual(serialNumber)
    })

    test('can be converted to ASN.1 with required fields', () => {
        const version = 2 // X.509v3
        const serialNumber = 1234567890
        const signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })
        const subject = createSampleName()
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })

        const tbsCert = new Certificate.TBSCertificate({
            version: version,
            serialNumber: serialNumber,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
        })

        const asn1 = tbsCert.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(7) // version, subjectUniqueID, serialNumber, extensions, signature, issuer, validity, subject, spki

        // First element should be version
        const versionBlock = asn1.valueBlock.value[0]
        expect(versionBlock).toBeInstanceOf(asn1js.Constructed)
        expect((versionBlock as asn1js.Constructed).idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect((versionBlock as asn1js.Constructed).idBlock.tagNumber).toEqual(
            0,
        ) // [0]

        // Second element should be serialNumber
        const serialNumberBlock = asn1.valueBlock.value[1]
        expect(serialNumberBlock).toBeInstanceOf(asn1js.Integer)
    })

    test('can be converted to ASN.1 with all fields', () => {
        const version = 2 // X.509v3
        const serialNumber = 1234567890
        const signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })
        const subject = createSampleName()
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })
        const issuerUniqueID = new Uint8Array([10, 11, 12])
        const subjectUniqueID = new Uint8Array([13, 14, 15])

        // Create extensions
        const keyUsageExt = new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: new KeyUsage({
                digitalSignature: true,
                keyEncipherment: true,
            }),
        })
        // keyUsage
        const basicConstraintsExt = new Extension({
            extnID: '2.5.29.19',
            critical: true,
            extnValue: new BasicConstraints({
                cA: true,
            }),
        })
        // basicConstraints

        const tbsCert = new Certificate.TBSCertificate({
            version: version,
            serialNumber: serialNumber,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
            issuerUniqueID: issuerUniqueID,
            subjectUniqueID: subjectUniqueID,
            extensions: [keyUsageExt, basicConstraintsExt],
        })

        const asn1 = tbsCert.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(10) // version, serialNumber, signature, issuer, validity, subject, spki, issuerUniqueID, subjectUniqueID, extensions

        // Last element should be extensions
        const extensionsBlock = asn1.valueBlock.value[9]
        expect(extensionsBlock).toBeInstanceOf(asn1js.Constructed)
        expect(
            (extensionsBlock as asn1js.Constructed).idBlock.tagClass,
        ).toEqual(3) // CONTEXT-SPECIFIC
        expect(
            (extensionsBlock as asn1js.Constructed).idBlock.tagNumber,
        ).toEqual(3) // [3]
    })

    test('TBSCertificate toString snapshot', () => {
        const version = 2 // X.509v3
        const serialNumber = 1234567890
        const signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        const issuer = createSampleName()
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })
        const subject = createSampleName()
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })
        const issuerUniqueID = new Uint8Array([10, 11, 12])
        const subjectUniqueID = new Uint8Array([13, 14, 15])

        // Create extensions
        const keyUsageExt = new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: new KeyUsage({
                digitalSignature: true,
                keyEncipherment: true,
            }),
        })
        // keyUsage
        const basicConstraintsExt = new Extension({
            extnID: '2.5.29.19',
            critical: true,
            extnValue: new BasicConstraints({
                cA: true,
            }),
        })
        // basicConstraints

        const tbsCert = new Certificate.TBSCertificate({
            version: version,
            serialNumber: serialNumber,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
            issuerUniqueID: issuerUniqueID,
            subjectUniqueID: subjectUniqueID,
            extensions: [keyUsageExt, basicConstraintsExt],
        })

        expect(tbsCert.toString()).toMatchInlineSnapshot(`
          "[TBSCertificate] SEQUENCE :
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
            SEQUENCE :
              SEQUENCE :
                OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
              BIT STRING : 0000000100000010000000110000010000000101
            PRIMITIVE : 
            PRIMITIVE : 
            [3] :
              SEQUENCE :
                SEQUENCE :
                  OBJECT IDENTIFIER : 2.5.29.15
                  BOOLEAN: TRUE
                  OCTET STRING : 03040000a000
                SEQUENCE :
                  OBJECT IDENTIFIER : 2.5.29.19
                  BOOLEAN: TRUE
                  OCTET STRING : 30030101ff"
        `)
    })
})
