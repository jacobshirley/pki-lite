import { assert, describe, expect, test } from 'vitest'
import {
    TimeStampResp,
    PKIStatusInfo,
    PKIStatus,
    PKIFailureInfo,
    PKIFreeText,
} from './TimeStampResp.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'

describe('PKIFreeText', () => {
    test('can be created with single text', () => {
        const freeText = new PKIFreeText({ texts: ['Error message'] })
        expect(freeText.texts).toEqual(['Error message'])
    })

    test('can be created with multiple texts', () => {
        const texts = ['First message', 'Second message']
        const freeText = new PKIFreeText({ texts })
        expect(freeText.texts).toEqual(texts)
    })

    test('throws error for empty texts', () => {
        expect(() => new PKIFreeText({ texts: [] })).toThrow(
            'PKIFreeText must contain 1-255 text entries',
        )
    })

    test('throws error for too many texts', () => {
        const tooManyTexts = Array(256).fill('text')
        expect(() => new PKIFreeText({ texts: tooManyTexts })).toThrow(
            'PKIFreeText must contain 1-255 text entries',
        )
    })

    test('can be converted to ASN.1', () => {
        const freeText = new PKIFreeText({ texts: ['Test message'] })
        const asn1 = freeText.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(1)
        assert(asn1.valueBlock.value[0] instanceof asn1js.Utf8String)
        expect(asn1.valueBlock.value[0].valueBlock.value).toBe('Test message')
    })

    test('roundtrip conversion preserves data', () => {
        const texts = ['First message', 'Second message', 'Third message']
        const original = new PKIFreeText({ texts })
        const asn1 = original.toAsn1()
        const recreated = PKIFreeText.fromAsn1(asn1)

        expect(recreated.texts).toEqual(texts)
    })
})

describe('PKIStatusInfo', () => {
    test('can be created with status only', () => {
        const statusInfo = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        expect(statusInfo.status).toBe(PKIStatus.GRANTED)
        expect(statusInfo.statusString).toBeUndefined()
        expect(statusInfo.failInfo).toBeUndefined()
    })

    test('can be created with all parameters', () => {
        const statusString = new PKIFreeText({ texts: ['Request granted'] })
        const statusInfo = new PKIStatusInfo({
            status: PKIStatus.GRANTED,
            statusString,
            failInfo: undefined,
        })

        expect(statusInfo.status).toBe(PKIStatus.GRANTED)
        expect(statusInfo.statusString).toBe(statusString)
        expect(statusInfo.failInfo).toBeUndefined()
    })

    test('can be created with failure info', () => {
        const statusString = new PKIFreeText({ texts: ['Bad request format'] })
        const statusInfo = new PKIStatusInfo({
            status: PKIStatus.REJECTION,
            statusString,
            failInfo: PKIFailureInfo.BAD_DATA_FORMAT,
        })

        expect(statusInfo.status).toBe(PKIStatus.REJECTION)
        expect(statusInfo.failInfo).toBe(PKIFailureInfo.BAD_DATA_FORMAT)
    })

    test('isSuccess returns correct values', () => {
        expect(
            new PKIStatusInfo({ status: PKIStatus.GRANTED }).isSuccess(),
        ).toBe(true)
        expect(
            new PKIStatusInfo({
                status: PKIStatus.GRANTED_WITH_MODS,
            }).isSuccess(),
        ).toBe(true)
        expect(
            new PKIStatusInfo({ status: PKIStatus.REJECTION }).isSuccess(),
        ).toBe(false)
        expect(
            new PKIStatusInfo({ status: PKIStatus.WAITING }).isSuccess(),
        ).toBe(false)
    })

    test('getStatusDescription returns correct descriptions', () => {
        expect(
            new PKIStatusInfo({
                status: PKIStatus.GRANTED,
            }).getStatusDescription(),
        ).toBe('granted')
        expect(
            new PKIStatusInfo({
                status: PKIStatus.GRANTED_WITH_MODS,
            }).getStatusDescription(),
        ).toBe('granted with modifications')
        expect(
            new PKIStatusInfo({
                status: PKIStatus.REJECTION,
            }).getStatusDescription(),
        ).toBe('rejection')
        expect(
            new PKIStatusInfo({
                status: PKIStatus.WAITING,
            }).getStatusDescription(),
        ).toBe('waiting')
        expect(
            new PKIStatusInfo({
                status: PKIStatus.REVOCATION_WARNING,
            }).getStatusDescription(),
        ).toBe('revocation warning')
        expect(
            new PKIStatusInfo({
                status: PKIStatus.REVOCATION_NOTIFICATION,
            }).getStatusDescription(),
        ).toBe('revocation notification')
    })

    test('can be converted to ASN.1', () => {
        const statusString = new PKIFreeText({ texts: ['Test message'] })
        const statusInfo = new PKIStatusInfo({
            status: PKIStatus.GRANTED,
            statusString,
        })
        const asn1 = statusInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        // Status
        assert(asn1.valueBlock.value[0] instanceof asn1js.Integer)
        expect(asn1.valueBlock.value[0].valueBlock.valueDec).toBe(
            PKIStatus.GRANTED,
        )

        // StatusString
        assert(asn1.valueBlock.value[1] instanceof asn1js.Sequence)
    })

    test('roundtrip conversion preserves data', () => {
        const statusString = new PKIFreeText({
            texts: ['Request granted with modifications'],
        })
        const original = new PKIStatusInfo({
            status: PKIStatus.GRANTED_WITH_MODS,
            statusString,
            failInfo: undefined,
        })

        const asn1 = original.toAsn1()
        const recreated = PKIStatusInfo.fromAsn1(asn1)

        expect(recreated.status).toBe(PKIStatus.GRANTED_WITH_MODS)
        expect(recreated.statusString?.texts).toEqual([
            'Request granted with modifications',
        ])
        expect(recreated.failInfo).toBeUndefined()
    })
})

describe('TimeStampResp', () => {
    test('can be created with status only', () => {
        const status = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        const resp = new TimeStampResp({ status })

        expect(resp.status).toBe(status)
        expect(resp.timeStampToken).toBeUndefined()
    })

    test('can be created with timestamp token', () => {
        const status = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        const timeStampToken = new ContentInfo({
            contentType: OIDs.PKCS7.SIGNED_DATA,
        })
        const resp = new TimeStampResp({ status, timeStampToken })

        expect(resp.status).toBe(status)
        expect(resp.timeStampToken).toBe(timeStampToken)
    })

    test('can be converted to ASN.1 with status only', () => {
        const status = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        const resp = new TimeStampResp({ status })
        const asn1 = resp.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(1)

        // Status
        assert(asn1.valueBlock.value[0] instanceof asn1js.Sequence)
    })

    test('can be converted to ASN.1 with timestamp token', () => {
        const status = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        const timeStampToken = new ContentInfo({
            contentType: OIDs.PKCS7.SIGNED_DATA,
        })
        const resp = new TimeStampResp({ status, timeStampToken })
        const asn1 = resp.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        // Status
        assert(asn1.valueBlock.value[0] instanceof asn1js.Sequence)

        // TimeStampToken
        assert(asn1.valueBlock.value[1] instanceof asn1js.Sequence)
    })

    test('can be created from ASN.1', () => {
        const status = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        const timeStampToken = new ContentInfo({
            contentType: OIDs.PKCS7.SIGNED_DATA,
        })
        const original = new TimeStampResp({ status, timeStampToken })

        const asn1 = original.toAsn1()
        const recreated = TimeStampResp.fromAsn1(asn1)

        expect(recreated.status.status).toBe(PKIStatus.GRANTED)
        expect(recreated.timeStampToken?.contentType.toString()).toBe(
            OIDs.PKCS7.SIGNED_DATA,
        )
    })

    test('roundtrip conversion preserves data', () => {
        const statusString = new PKIFreeText({ texts: ['Timestamp granted'] })
        const status = new PKIStatusInfo({
            status: PKIStatus.GRANTED,
            statusString,
        })
        const timeStampToken = new ContentInfo({
            contentType: OIDs.PKCS7.SIGNED_DATA,
            content: 'test content',
        })
        const original = new TimeStampResp({ status, timeStampToken })

        const asn1 = original.toAsn1()
        const recreated = TimeStampResp.fromAsn1(asn1)
        const asn1Again = recreated.toAsn1()

        expect(original.toDer()).toEqual(recreated.toDer())
        expect(asn1.toBER(false)).toEqual(asn1Again.toBER(false))
    })

    test('fromAsn1 throws error for invalid structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 1 })

        expect(() => TimeStampResp.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for insufficient elements', () => {
        const invalidAsn1 = new asn1js.Sequence({
            value: [], // No elements
        })

        expect(() => TimeStampResp.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected at least 1 element',
        )
    })

    test('isSuccess delegates to status', () => {
        const grantedStatus = new PKIStatusInfo({ status: PKIStatus.GRANTED })
        const rejectedStatus = new PKIStatusInfo({
            status: PKIStatus.REJECTION,
        })

        const grantedResp = new TimeStampResp({ status: grantedStatus })
        const rejectedResp = new TimeStampResp({ status: rejectedStatus })

        expect(grantedResp.isSuccess()).toBe(true)
        expect(rejectedResp.isSuccess()).toBe(false)
    })

    test('getTimeStampTokenDer returns correct data', () => {
        const status = new PKIStatusInfo({ status: PKIStatus.GRANTED })

        // Without token
        const respWithoutToken = new TimeStampResp({ status })
        expect(() => respWithoutToken.getTimeStampTokenDer()).toThrow()

        // With token
        const timeStampToken = new ContentInfo({
            contentType: OIDs.PKCS7.DATA,
            content: 'test content',
        })
        const respWithToken = new TimeStampResp({ status, timeStampToken })
        const tokenDer = respWithToken.getTimeStampTokenDer()

        expect(tokenDer).toBeInstanceOf(Uint8Array)
        expect(tokenDer?.length).toBeGreaterThan(0)
        expect(tokenDer).toEqual(timeStampToken.toDer())
    })

    test('handles rejection response correctly', () => {
        const statusString = new PKIFreeText({
            texts: ['Invalid request format'],
        })
        const status = new PKIStatusInfo({
            status: PKIStatus.REJECTION,
            statusString,
            failInfo: PKIFailureInfo.BAD_DATA_FORMAT,
        })
        const resp = new TimeStampResp({ status }) // No token for rejection

        expect(resp.isSuccess()).toBe(false)
        expect(resp.status.getStatusDescription()).toBe('rejection')
        expect(resp.timeStampToken).toBeUndefined()
    })
})
