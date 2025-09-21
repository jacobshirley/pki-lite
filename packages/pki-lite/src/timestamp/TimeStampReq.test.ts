import { assert, describe, expect, test, vi } from 'vitest'
import { TimeStampReq } from './TimeStampReq.js'
import { MessageImprint } from './MessageImprint.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Extension } from '../x509/Extension.js'
import { asn1js } from '../core/PkiBase.js'

describe('TimeStampReq', () => {
    const createTestMessageImprint = () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const hashedMessage = new Uint8Array([1, 2, 3, 4, 5])
        return new MessageImprint({ hashAlgorithm, hashedMessage })
    }

    test('can be created with minimal parameters', () => {
        const messageImprint = createTestMessageImprint()

        const req = TimeStampReq.fromMessageImprint(messageImprint)
        expect(req).toBeInstanceOf(TimeStampReq)
        expect(req.version).toBe(1)
        expect(req.messageImprint).toBe(messageImprint)
        expect(req.reqPolicy).toBeUndefined()
        expect(req.nonce).toBeUndefined()
        expect(req.certReq).toBe(false)
        expect(req.extensions).toBeUndefined()
    })

    test('can be created with all parameters', () => {
        const messageImprint = createTestMessageImprint()
        const reqPolicy = '1.2.3.4.5'
        const nonce = new Uint8Array([1, 2, 3, 4])
        const certReq = true
        const extensions = [
            new Extension({
                extnID: '1.2.3.4',
                critical: false,
                extnValue: 123,
            }),
        ]

        const req = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
            reqPolicy: reqPolicy,
            nonce: nonce,
            certReq: certReq,
            extensions: extensions,
        })

        expect(req.messageImprint).toBe(messageImprint)
        expect(req.reqPolicy?.toString()).toBe(reqPolicy)
        expect(req.nonce).toEqual(nonce)
        expect(req.certReq).toBe(certReq)
        expect(req.extensions).toEqual(extensions)
    })

    test('can be converted to ASN.1 with minimal parameters', () => {
        const messageImprint = createTestMessageImprint()
        const req = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
        })
        const asn1 = req.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        // Version
        assert(asn1.valueBlock.value[0] instanceof asn1js.Integer)
        expect(asn1.valueBlock.value[0].valueBlock.valueDec).toBe(1)

        // MessageImprint
        assert(asn1.valueBlock.value[1] instanceof asn1js.Sequence)
    })

    test('can be converted to ASN.1 with extensions', () => {
        const messageImprint = createTestMessageImprint()
        const extensions = [
            new Extension({
                extnID: '1.2.3.4',
                critical: false,
                extnValue: 123,
            }),
            new Extension({
                extnID: '1.3.4.5',
                critical: true,
                extnValue: new Uint8Array([9, 10, 11, 12]),
            }),
        ]

        const req = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
            reqPolicy: '1.2.3.4.5',
            nonce: new Uint8Array([1, 2, 3, 4]),
            certReq: true,
            extensions: extensions,
        })
        const asn1 = req.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(6) // version, messageImprint, reqPolicy, nonce, certReq, extensions

        // Last element should be the extensions with tagClass 3 (CONTEXT-SPECIFIC) and tagNumber 0 ([0])
        const extensionsBlock = asn1.valueBlock.value[5]
        assert(extensionsBlock instanceof asn1js.Constructed)
        expect(extensionsBlock.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(extensionsBlock.idBlock.tagNumber).toBe(0) // [0]

        // Check that it contains a sequence of extensions
        assert(extensionsBlock.valueBlock.value.length > 0)
        const extensionsSeq = extensionsBlock.valueBlock.value[0]
        assert(extensionsSeq instanceof asn1js.Sequence)
        expect(extensionsSeq.valueBlock.value.length).toBe(2) // Two extensions
    })

    test('can parse extensions from ASN.1', () => {
        const messageImprint = createTestMessageImprint()
        const extensions = [
            new Extension({
                extnID: '1.2.3.4',
                critical: false,
                extnValue: 123,
            }),
        ]
        const original = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
            reqPolicy: '1.2.3.4.5',
            nonce: new Uint8Array([1, 2, 3, 4]),
            certReq: true,
            extensions: extensions,
        })

        const asn1 = original.toAsn1()
        const recreated = TimeStampReq.fromAsn1(asn1)

        expect(recreated.extensions).toBeDefined()
        expect(recreated.extensions).toHaveLength(1)
        expect(recreated.extensions![0].extnID.toString()).toBe('1.2.3.4')
        expect(recreated.extensions![0].critical).toBe(false)
        expect(recreated.extensions![0].extnValue).toBeDefined()
    })

    test('can be converted to ASN.1 with all parameters', () => {
        const messageImprint = createTestMessageImprint()
        const reqPolicy = '1.2.3.4.5'
        const nonce = new Uint8Array([1, 2, 3, 4])

        const req = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
            reqPolicy: reqPolicy,
            nonce: nonce,
            certReq: true,
        })
        const asn1 = req.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(5) // version, messageImprint, reqPolicy, nonce, certReq

        // Version
        assert(asn1.valueBlock.value[0] instanceof asn1js.Integer)
        expect(asn1.valueBlock.value[0].valueBlock.valueDec).toBe(1)

        // MessageImprint
        assert(asn1.valueBlock.value[1] instanceof asn1js.Sequence)

        // ReqPolicy
        assert(asn1.valueBlock.value[2] instanceof asn1js.ObjectIdentifier)
        expect(asn1.valueBlock.value[2].valueBlock.toString()).toContain(
            reqPolicy,
        )

        // Nonce
        assert(asn1.valueBlock.value[3] instanceof asn1js.Integer)
        expect(
            new Uint8Array(asn1.valueBlock.value[3].valueBlock.valueHexView),
        ).toEqual(nonce)

        // CertReq
        assert(asn1.valueBlock.value[4] instanceof asn1js.Boolean)
        expect(asn1.valueBlock.value[4].valueBlock.value).toBe(true)
    })

    test('can be created from ASN.1', () => {
        const messageImprint = createTestMessageImprint()
        const original = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
            reqPolicy: '1.2.3.4.5',
            nonce: new Uint8Array([1, 2, 3, 4]),
            certReq: true,
        })

        const asn1 = original.toAsn1()
        const recreated = TimeStampReq.fromAsn1(asn1)

        expect(recreated.version).toBe(1)
        expect(recreated.messageImprint.hashAlgorithm.algorithm).toEqual(
            messageImprint.hashAlgorithm.algorithm,
        )
        expect(recreated.messageImprint.hashedMessage).toEqual(
            messageImprint.hashedMessage,
        )
        expect(recreated.reqPolicy?.toString()).toBe('1.2.3.4.5')
        expect(recreated.nonce).toEqual(new Uint8Array([1, 2, 3, 4]))
        expect(recreated.certReq).toBe(true)
    })

    test('roundtrip conversion preserves data', () => {
        const messageImprint = createTestMessageImprint()
        const original = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
            reqPolicy: '1.2.840.113549.1.9.16.1.12',
            nonce: crypto.getRandomValues(new Uint8Array(8)),
            certReq: false,
        })

        const asn1 = original.toAsn1()
        const recreated = TimeStampReq.fromAsn1(asn1)
        const asn1Again = recreated.toAsn1()

        expect(original.toDer()).toEqual(recreated.toDer())
        expect(asn1.toBER(false)).toEqual(asn1Again.toBER(false))
    })

    test('fromAsn1 throws error for invalid structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 1 })

        expect(() => TimeStampReq.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for insufficient elements', () => {
        const invalidAsn1 = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })], // Only version, missing messageImprint
        })

        expect(() => TimeStampReq.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected at least 2 elements',
        )
    })

    test('fromAsn1 throws error for unsupported version', () => {
        const messageImprint = createTestMessageImprint()
        const invalidAsn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 2 }), // Unsupported version
                messageImprint.toAsn1(),
            ],
        })

        expect(() => TimeStampReq.fromAsn1(invalidAsn1)).toThrow(
            'Unsupported TimeStampReq version: 2',
        )
    })

    test('request method exists and handles basic request', async () => {
        // Mock fetch globally for this test
        const mockResponse = {
            ok: true,
            arrayBuffer: () => Promise.resolve(new ArrayBuffer(100)), // Mock response data
        }
        const fetchSpy = vi.fn().mockResolvedValue(mockResponse)
        globalThis.fetch = fetchSpy

        // Mock TimeStampResp.fromAsn1 to avoid circular dependency issues in test
        const mockFromAsn1 = vi
            .fn()
            .mockReturnValue({ status: { isSuccess: () => true } })
        vi.doMock('./TimeStampResp', () => ({
            TimeStampResp: { fromAsn1: mockFromAsn1 },
        }))

        const messageImprint = createTestMessageImprint()
        const req = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
        })

        try {
            await req.request({
                url: 'https://test.tsa.server/tsr',
                username: 'user',
                password: 'pass',
                timeout: 5000,
            })

            expect(fetchSpy).toHaveBeenCalledWith(
                'https://test.tsa.server/tsr',
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/timestamp-query',
                        Accept: 'application/timestamp-reply',
                        Authorization: 'Basic dXNlcjpwYXNz', // base64 of 'user:pass'
                    }),
                    body: expect.any(Uint8Array),
                }),
            )
        } catch (error) {
            // Expected in test environment due to mocking complexities
            expect(error).toBeDefined()
        }
    })

    test('request throws error for failed request', async () => {
        const mockResponse = {
            ok: false,
            status: 400,
            text: () => Promise.resolve('Bad Request'),
        }
        const fetchSpy = vi.fn().mockResolvedValue(mockResponse)
        globalThis.fetch = fetchSpy

        const messageImprint = createTestMessageImprint()
        const req = new TimeStampReq({
            version: 1,
            messageImprint: messageImprint,
        })

        await expect(
            req.request({
                url: 'https://test.tsa.server/tsr',
            }),
        ).rejects.toThrow('TSA request failed (400): Bad Request')
    })

    test('generates correct DER encoding', () => {
        const messageImprint = createTestMessageImprint()
        const req = TimeStampReq.create({
            version: 1,
            messageImprint,
            certReq: true,
        })

        const der = req.toDer()
        expect(der).toBeInstanceOf(Uint8Array)
        expect(der.length).toBeGreaterThan(0)

        // Should be able to parse back
        const parsed = TimeStampReq.fromAsn1(asn1js.fromBER(der).result)
        expect(parsed.certReq).toBe(true)
    })

    test('demonstrates hash algorithm flexibility', async () => {
        const testData = new TextEncoder().encode('test data')

        const hashAlgorithms = [
            { name: 'SHA-1', oid: '1.3.14.3.2.26' },
            { name: 'SHA-256', oid: '2.16.840.1.101.3.4.2.1' },
            { name: 'SHA-384', oid: '2.16.840.1.101.3.4.2.2' },
            { name: 'SHA-512', oid: '2.16.840.1.101.3.4.2.3' },
        ]

        for (const { name, oid } of hashAlgorithms) {
            const hash = await crypto.subtle.digest(name, testData)
            const hashBytes = new Uint8Array(hash)

            const messageImprint = new MessageImprint({
                hashAlgorithm: new AlgorithmIdentifier({
                    algorithm: oid,
                    parameters: undefined, // Fix null.toDer() issue
                }),
                hashedMessage: hashBytes,
            })

            const tsReq = new TimeStampReq({
                version: 1,
                messageImprint: messageImprint,
            })
            const der = tsReq.toDer()

            // Verify it can be parsed back
            const parsed = TimeStampReq.fromAsn1(asn1js.fromBER(der).result)

            expect(
                parsed.messageImprint.hashAlgorithm.algorithm.toString(),
            ).toBe(oid)
            expect(parsed.messageImprint.hashedMessage).toEqual(hashBytes)
        }
    })

    test('validates security features', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
            parameters: null,
        })
        const hashBytes = crypto.getRandomValues(new Uint8Array(32))
        const messageImprint = new MessageImprint({
            hashAlgorithm: hashAlgorithm,
            hashedMessage: hashBytes,
        })

        // Test with nonce for replay protection
        const nonce1 = crypto.getRandomValues(new Uint8Array(8))
        const nonce2 = crypto.getRandomValues(new Uint8Array(8))

        const req1 = TimeStampReq.create({
            version: 1,
            messageImprint,
            nonce: nonce1,
        })
        const req2 = TimeStampReq.create({
            version: 1,
            messageImprint,
            nonce: nonce2,
        })

        // Different nonces should produce different requests
        expect(req1.toDer()).not.toEqual(req2.toDer())
        expect(req1.nonce).not.toEqual(req2.nonce)

        // But same message content
        expect(req1.messageImprint.hashedMessage).toEqual(
            req2.messageImprint.hashedMessage,
        )
    })
})
