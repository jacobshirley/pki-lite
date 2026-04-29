import { describe, it, expect } from 'vitest'
import { TimeStampReq } from '../../timestamp/TimeStampReq.js'
import { MessageImprint } from '../../timestamp/MessageImprint.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'

describe('TimeStampReqBuilder', () => {
    it('builds a basic timestamp request from data', async () => {
        const data = new TextEncoder().encode('Hello, world!')

        const tsReq = await TimeStampReq.builder()
            .setData(data)
            .setHashAlgorithm('SHA-256')
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.messageImprint).toBeDefined()
        expect(tsReq.messageImprint.hashAlgorithm.algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.1', // SHA-256
        )

        // Round-trip
        const der = tsReq.toDer()
        const decoded = TimeStampReq.fromDer(der)
        expect(decoded.toDer()).toEqual(tsReq.toDer())
    })

    it('builds a timestamp request with string data', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Test message for timestamping')
            .setHashAlgorithm('SHA-256')
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.messageImprint).toBeDefined()
    })

    it('builds a timestamp request with pre-computed message imprint', async () => {
        const hashAlg = AlgorithmIdentifier.digestAlgorithm('SHA-256')
        const data = new TextEncoder().encode('Test data')
        const hash = await hashAlg.digest(data)

        const messageImprint = new MessageImprint({
            hashAlgorithm: hashAlg,
            hashedMessage: hash,
        })

        const tsReq = await TimeStampReq.builder()
            .setMessageImprint(messageImprint)
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.messageImprint.hashedMessage).toEqual(hash)
    })

    it('builds a timestamp request with nonce', async () => {
        const nonce = crypto.getRandomValues(new Uint8Array(8))

        const tsReq = await TimeStampReq.builder()
            .setData('Test data')
            .setNonce(nonce)
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.nonce).toBeDefined()
        expect(tsReq.nonce).toBeInstanceOf(Uint8Array)
    })

    it('builds a timestamp request with random nonce', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Test data')
            .setRandomNonce(16)
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.nonce).toBeDefined()
    })

    it('builds a timestamp request with certReq flag', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Test data')
            .setCertReq(true)
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.certReq).toBe(true)
    })

    it('builds a timestamp request without certReq flag', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Test data')
            .setCertReq(false)
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.certReq).toBe(false)
    })

    it('builds a timestamp request with policy OID', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Test data')
            .setReqPolicy('1.2.3.4.5')
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.reqPolicy).toBeDefined()
        expect(tsReq.reqPolicy!.toString()).toBe('1.2.3.4.5')
    })

    it('builds a timestamp request with SHA-512', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Test data')
            .setHashAlgorithm('SHA-512')
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.messageImprint.hashAlgorithm.algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.3', // SHA-512
        )
    })

    it('builds a timestamp request with all options', async () => {
        const tsReq = await TimeStampReq.builder()
            .setData('Complete test data')
            .setHashAlgorithm('SHA-256')
            .setRandomNonce(8)
            .setCertReq(true)
            .setReqPolicy('1.3.6.1.4.1.4146.2.3')
            .setVersion(1)
            .build()

        expect(tsReq).toBeInstanceOf(TimeStampReq)
        expect(tsReq.version).toBe(1)
        expect(tsReq.messageImprint).toBeDefined()
        expect(tsReq.nonce).toBeDefined()
        expect(tsReq.certReq).toBe(true)
        expect(tsReq.reqPolicy).toBeDefined()
    })

    it('defaults to SHA-256 when hash algorithm not specified', async () => {
        const tsReq = await TimeStampReq.builder().setData('Test data').build()

        expect(tsReq.messageImprint.hashAlgorithm.algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.1', // SHA-256
        )
    })
})
