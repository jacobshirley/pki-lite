import { describe, it, expect } from 'vitest'
import { Data } from './Data.js'

describe('Data', () => {
    it('should create Data object', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const dataObject = new Data({ data })

        expect(dataObject.data).toBe(data)
    })

    it('should convert to ASN.1 structure', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const dataObject = new Data({ data })
        const asn1 = dataObject.toAsn1()

        expect(asn1.constructor.name).toBe('OctetString')
    })

    it('should convert to string', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const dataObject = new Data({ data })
        const str = dataObject.toString()

        expect(typeof str).toBe('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('should handle empty data', () => {
        const data = new Uint8Array([])
        const dataObject = new Data({ data })

        expect(dataObject.data).toBe(data)
        expect(dataObject.data.length).toBe(0)

        const asn1 = dataObject.toAsn1()
        expect(asn1.constructor.name).toBe('OctetString')
    })

    it('Data toString snapshot', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const dataObject = new Data({ data })
        expect(dataObject.toString()).toMatchInlineSnapshot(
            `"[Data] OCTET STRING : 0102030405"`,
        )
    })

    it('Data toString snapshot empty', () => {
        const data = new Uint8Array([])
        const dataObject = new Data({ data })
        expect(dataObject.toString()).toMatchInlineSnapshot(
            `"[Data] OCTET STRING : "`,
        )
    })

    it('Data toPem snapshot', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const dataObject = new Data({ data })
        expect(dataObject.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN DATA-----
          BAUBAgMEBQ==
          -----END DATA-----"
        `)
    })

    it('Data toPem snapshot empty', () => {
        const data = new Uint8Array([])
        const dataObject = new Data({ data })
        expect(dataObject.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN DATA-----
          BAA=
          -----END DATA-----"
        `)
    })
})
