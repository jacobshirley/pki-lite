import { describe, it, expect, vi } from 'vitest'
import {
    RevocationInfoArchival,
    OtherRevInfo,
} from './RevocationInfoArchival.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { asn1js } from '../core/PkiBase.js'

describe('RevocationInfoArchival', () => {
    it('should instantiate with empty options', () => {
        const ria = new RevocationInfoArchival({})
        expect(ria.crls).toBeUndefined()
        expect(ria.ocsps).toBeUndefined()
        expect(ria.otherRevInfo).toBeUndefined()
    })

    it('should instantiate with all options', () => {
        const crl = { toAsn1: vi.fn() } as unknown as CertificateList
        const ocsp = { toAsn1: vi.fn() } as unknown as OCSPResponse
        const ori = { toAsn1: vi.fn() } as unknown as OtherRevInfo
        const ria = new RevocationInfoArchival({
            crls: [crl],
            ocsps: [ocsp],
            otherRevInfo: [ori],
        })
        expect(ria.crls).toHaveLength(1)
        expect(ria.ocsps).toHaveLength(1)
        expect(ria.otherRevInfo).toHaveLength(1)
    })

    it('should convert to ASN.1 sequence', () => {
        const crl = {
            toAsn1: vi.fn(() => new asn1js.Null()),
        } as unknown as CertificateList
        const ocsp = {
            toAsn1: vi.fn(() => new asn1js.Null()),
        } as unknown as OCSPResponse
        const ori = {
            toAsn1: vi.fn(() => new asn1js.Null()),
        } as unknown as OtherRevInfo
        const ria = new RevocationInfoArchival({
            crls: [crl],
            ocsps: [ocsp],
            otherRevInfo: [ori],
        })
        const asn1 = ria.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3)
        expect(ria.toString()).toMatchInlineSnapshot(`
      "[RevocationInfoArchival] SEQUENCE :
        [0] :
          SEQUENCE :
            NULL
        [1] :
          SEQUENCE :
            NULL
        [2] :
          SEQUENCE :
            NULL"
    `)
    })

    it('should throw if fromAsn1 is not a sequence', () => {
        expect(() =>
            RevocationInfoArchival.fromAsn1(new asn1js.Null()),
        ).toThrow('Invalid ASN.1 structure: expected SEQUENCE')
    })
})
