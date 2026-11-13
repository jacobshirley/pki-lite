import { describe, it, expect } from 'vitest'
import {
    Asn1Node,
    der,
    derToAsn1,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
import { SignerLocation, PostalAddress } from './SignerLocation.js'
import { DirectoryString } from '../DirectoryString.js'
import { UTF8String } from '../../asn1/UTF8String.js'

function tagOf(block: Asn1Node) {
    return {
        tagClass: block.tagClass,
        tagNumber: block.tag,
        isConstructed: block.constructed,
    }
}

describe('SignerLocation', () => {
    it('constructs empty and encodes to empty SEQUENCE', () => {
        const sl = new SignerLocation()
        const asn1 = sl.toAsn1()
        expect(asn1.is(UniversalTag.Sequence)).toBe(true)
        expect(asn1.children.length).toEqual(0)
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
        const seq = sl.toAsn1()
        expect(seq.children.length).toEqual(3)

        const [c, l, p] = seq.children
        expect(tagOf(c)).toEqual({
            tagClass: TagClass.Context,
            tagNumber: 0,
            isConstructed: true,
        })
        expect(tagOf(l)).toEqual({
            tagClass: TagClass.Context,
            tagNumber: 1,
            isConstructed: true,
        })
        expect(tagOf(p)).toEqual({
            tagClass: TagClass.Context,
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
        // Context-specific tagged elements holding universal string values
        const countryInner = der.utf8String('US').explicit(0)
        const localityInner = der.utf8String('Seattle').explicit(1)

        const postalSeqInner = der
            .sequence([
                der.utf8String('123 Main St'),
                der.utf8String('Suite 100'),
            ])
            .explicit(2)

        const outer = der.sequence([
            countryInner,
            localityInner,
            postalSeqInner,
        ])

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
        expect(() => SignerLocation.fromAsn1(der.nullValue())).toThrow(
            'Expected ASN.1 Sequence for SignerLocation',
        )
    })

    it('round-trips through DER', () => {
        const sl = new SignerLocation({
            countryName: new UTF8String({ value: 'GB' }) as DirectoryString,
            localityName: new UTF8String({
                value: 'London',
            }) as DirectoryString,
            postalAddress: [
                new UTF8String({ value: '1 High St' }) as DirectoryString,
            ],
        })
        const parsed = SignerLocation.fromAsn1(derToAsn1(sl.toDer()))
        expect(parsed.countryName?.toString()).toBe('GB')
        expect(parsed.localityName?.toString()).toBe('London')
        expect([...(parsed.postalAddress ?? [])].map(String)).toEqual([
            '1 High St',
        ])
        expect(parsed.toDer()).toEqual(sl.toDer())
    })
})
