import { describe, it, expect } from 'vitest'
import { asn1js } from '../../core/PkiBase.js'
import { SignerLocation, PostalAddress } from './SignerLocation.js'
import { DirectoryString } from '../DirectoryString.js'
import { UTF8String } from '../../asn1/UTF8String.js'

function tagOf(block: asn1js.BaseBlock) {
    return {
        tagClass: block.idBlock.tagClass,
        tagNumber: block.idBlock.tagNumber,
        isConstructed: block.idBlock.isConstructed,
    }
}

describe('SignerLocation', () => {
    it('constructs empty and encodes to empty SEQUENCE', () => {
        const sl = new SignerLocation()
        const asn1 = sl.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect((asn1 as asn1js.Sequence).valueBlock.value.length).toEqual(0)
    })

    it('encodes tagged fields correctly', () => {
        const country = new UTF8String({ value: 'US' }) as DirectoryString
        const locality = new UTF8String({ value: 'Seattle' }) as DirectoryString
        const addr = [
            new UTF8String({ value: '123 Main St' }) as DirectoryString,
            new UTF8String({ value: 'Suite 100' }) as DirectoryString,
        ]
        const sl = new SignerLocation({
            countryName: country,
            localityName: locality,
            postalAddress: addr,
        })
        const seq = sl.toAsn1() as asn1js.Sequence
        expect(seq.valueBlock.value.length).toEqual(3)

        const [c, l, p] = seq.valueBlock.value
        expect(tagOf(c)).toEqual({
            tagClass: 3,
            tagNumber: 0,
            isConstructed: true,
        })
        expect(tagOf(l)).toEqual({
            tagClass: 3,
            tagNumber: 1,
            isConstructed: true,
        })
        expect(tagOf(p)).toEqual({
            tagClass: 3,
            tagNumber: 2,
            isConstructed: true,
        })
    })

    it('PostalAddress enforces max size of 6', () => {
        const six = new PostalAddress(
            new UTF8String({ value: '1' }) as DirectoryString,
            new UTF8String({ value: '2' }) as DirectoryString,
            new UTF8String({ value: '3' }) as DirectoryString,
            new UTF8String({ value: '4' }) as DirectoryString,
            new UTF8String({ value: '5' }) as DirectoryString,
            new UTF8String({ value: '6' }) as DirectoryString,
        )
        expect(six.length).toEqual(6)
        expect(() =>
            six.push(new UTF8String({ value: '7' }) as DirectoryString),
        ).toThrow('Max size exceeded: 6')
    })

    it('fromAsn1 decodes fields and preserves order', () => {
        // Build context-specific tagged elements with inner universal string values,
        // using asn1js directly so valueBlock.value is populated as DirectoryString expects.
        const countryInner = new asn1js.Utf8String({ value: 'US' })
        countryInner.idBlock.tagClass = 3
        countryInner.idBlock.tagNumber = 0
        countryInner.idBlock.isConstructed = true

        const localityInner = new asn1js.Utf8String({ value: 'Seattle' })
        localityInner.idBlock.tagClass = 3
        localityInner.idBlock.tagNumber = 1
        localityInner.idBlock.isConstructed = true

        const postalSeqInner = new asn1js.Sequence({
            value: [
                new asn1js.Utf8String({ value: '123 Main St' }),
                new asn1js.Utf8String({ value: 'Suite 100' }),
            ],
        })
        postalSeqInner.idBlock.tagClass = 3
        postalSeqInner.idBlock.tagNumber = 2
        postalSeqInner.idBlock.isConstructed = true

        const outer = new asn1js.Sequence({
            value: [countryInner, localityInner, postalSeqInner],
        })

        const parsed = SignerLocation.fromAsn1(outer)
        expect(parsed.countryName?.toHumanString()).toContain('US')
        expect(parsed.localityName?.toHumanString()).toContain('Seattle')
        expect(parsed.postalAddress).toBeInstanceOf(PostalAddress)
        // Verify the decoded postal address entries contain our values
        expect(parsed.postalAddress?.[0].toHumanString()).toContain(
            '123 Main St',
        )
        expect(parsed.postalAddress?.[1].toHumanString()).toContain('Suite 100')
    })

    it('fromAsn1 throws for non-sequence', () => {
        expect(() => SignerLocation.fromAsn1(new asn1js.Null())).toThrow(
            'Expected ASN.1 Sequence for SignerLocation',
        )
    })
})
