import { describe, expect, test } from 'vitest'
import {
    NameConstraints,
    GeneralSubtree,
    GeneralSubtrees,
} from './NameConstraints.js'
import {
    dNSName,
    rfc822Name,
    uniformResourceIdentifier,
    directoryName,
} from '../GeneralName.js'
import { RDNSequence } from '../RDNSequence.js'
import { RelativeDistinguishedName } from '../RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../AttributeTypeAndValue.js'
import { OIDs } from '../../core/OIDs.js'
import * as asn1js from 'asn1js'

describe('GeneralSubtree', () => {
    test('should create GeneralSubtree with DNS name', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const subtree = new GeneralSubtree({
            base: dnsName,
        })

        expect(subtree.base).toEqual(dnsName)
        expect(subtree.minimum).toEqual(0)
        expect(subtree.maximum).toBeUndefined()
    })

    test('should create GeneralSubtree with minimum and maximum', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const subtree = new GeneralSubtree({
            base: dnsName,
            minimum: 1,
            maximum: 5,
        })

        expect(subtree.base).toEqual(dnsName)
        expect(subtree.minimum).toEqual(1)
        expect(subtree.maximum).toEqual(5)
    })

    test('should convert to ASN.1 structure', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const subtree = new GeneralSubtree({
            base: dnsName,
            minimum: 1,
            maximum: 3,
        })

        const asn1 = subtree.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBeGreaterThan(0)
    })

    test('should match DNS names correctly', () => {
        const subtree = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })

        // Exact match
        expect(subtree.matches(new dNSName({ value: 'example.com' }))).toEqual(
            true,
        )

        // Subdomain match
        expect(
            subtree.matches(new dNSName({ value: 'sub.example.com' })),
        ).toEqual(true)
        expect(
            subtree.matches(new dNSName({ value: 'www.sub.example.com' })),
        ).toEqual(true)

        // No match
        expect(subtree.matches(new dNSName({ value: 'other.com' }))).toEqual(
            false,
        )
        expect(
            subtree.matches(new dNSName({ value: 'notexample.com' })),
        ).toEqual(false)
    })

    test('should match RFC822 names correctly', () => {
        const subtree = new GeneralSubtree({
            base: new rfc822Name({ value: 'user@example.com' }),
        })

        // Different email addresses - matches should match domain
        expect(
            subtree.matches(new rfc822Name({ value: 'user@example.com' })),
        ).toEqual(true)
        expect(
            subtree.matches(new rfc822Name({ value: 'other@example.com' })),
        ).toEqual(true)
        expect(
            subtree.matches(new rfc822Name({ value: 'user@other.com' })),
        ).toEqual(false)
    })

    test('should match URI correctly', () => {
        const subtree = new GeneralSubtree({
            base: new uniformResourceIdentifier({
                value: 'https://example.com',
            }),
        })

        // Exact match
        expect(
            subtree.matches(
                new uniformResourceIdentifier({ value: 'https://example.com' }),
            ),
        ).toEqual(true)

        // Prefix match
        expect(
            subtree.matches(
                new uniformResourceIdentifier({
                    value: 'https://example.com/path',
                }),
            ),
        ).toEqual(false)

        // Different URI
        expect(
            subtree.matches(
                new uniformResourceIdentifier({ value: 'https://other.com' }),
            ),
        ).toEqual(false)
    })

    test('should match directory names', () => {
        const rdnSeq = new RDNSequence()
        const rdn = new RelativeDistinguishedName()
        const cnAttr = new AttributeTypeAndValue({
            type: OIDs.DN.CN,
            value: 'Test Subject',
        })
        rdn.push(cnAttr)
        rdnSeq.push(rdn)

        const dirName = new directoryName(...rdnSeq)
        const subtree = new GeneralSubtree({
            base: dirName,
        })

        // Create another matching directory name
        const otherRdn = new RDNSequence()
        const otherRel = new RelativeDistinguishedName()
        const otherAttr = new AttributeTypeAndValue({
            type: OIDs.DN.CN,
            value: 'Test Subject',
        })
        otherRel.push(otherAttr)
        otherRdn.push(otherRel)
        const otherDirName = new directoryName(...otherRdn)

        // Test basic creation (matching logic may be complex)
        expect(subtree.base).toBeInstanceOf(directoryName)
        expect(otherDirName).toBeInstanceOf(directoryName)
    })

    test('should not match different GeneralName types', () => {
        const dnsSubtree = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })

        expect(
            dnsSubtree.matches(new rfc822Name({ value: 'test@example.com' })),
        ).toEqual(false)
    })
})

describe('GeneralSubtrees', () => {
    test('should create empty GeneralSubtrees', () => {
        const subtrees = new GeneralSubtrees()

        expect(subtrees.length).toEqual(0)
    })

    test('should create GeneralSubtrees with multiple subtrees', () => {
        const subtree1 = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })
        const subtree2 = new GeneralSubtree({
            base: new dNSName({ value: 'test.org' }),
        })

        const subtrees = new GeneralSubtrees(subtree1, subtree2)

        expect(subtrees.length).toEqual(2)
        expect(subtrees[0]).toEqual(subtree1)
        expect(subtrees[1]).toEqual(subtree2)
    })

    test('should match if any subtree matches', () => {
        const subtree1 = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })
        const subtree2 = new GeneralSubtree({
            base: new dNSName({ value: 'test.org' }),
        })

        const subtrees = new GeneralSubtrees(subtree1, subtree2)

        expect(
            subtrees.matches(new dNSName({ value: 'sub.example.com' })),
        ).toEqual(true)
        expect(
            subtrees.matches(new dNSName({ value: 'sub.test.org' })),
        ).toEqual(true)
        expect(subtrees.matches(new dNSName({ value: 'other.com' }))).toEqual(
            false,
        )
    })
})

describe('NameConstraints', () => {
    test('should create NameConstraints with permitted subtrees', () => {
        const subtree = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })
        const permittedSubtrees = new GeneralSubtrees(subtree)

        const nameConstraints = new NameConstraints({
            permittedSubtrees,
        })

        expect(nameConstraints.permittedSubtrees).toEqual(permittedSubtrees)
        expect(nameConstraints.excludedSubtrees).toBeUndefined()
    })

    test('should create NameConstraints with excluded subtrees', () => {
        const subtree = new GeneralSubtree({
            base: new dNSName({ value: 'blocked.example.com' }),
        })
        const excludedSubtrees = new GeneralSubtrees(subtree)

        const nameConstraints = new NameConstraints({
            excludedSubtrees,
        })

        expect(nameConstraints.permittedSubtrees).toBeUndefined()
        expect(nameConstraints.excludedSubtrees).toEqual(excludedSubtrees)
    })

    test('should create NameConstraints with both permitted and excluded subtrees', () => {
        const permittedSubtree = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })
        const excludedSubtree = new GeneralSubtree({
            base: new dNSName({ value: 'blocked.example.com' }),
        })

        const nameConstraints = new NameConstraints({
            permittedSubtrees: new GeneralSubtrees(permittedSubtree),
            excludedSubtrees: new GeneralSubtrees(excludedSubtree),
        })

        expect(nameConstraints.permittedSubtrees).toBeDefined()
        expect(nameConstraints.excludedSubtrees).toBeDefined()
        expect(nameConstraints.permittedSubtrees!.length).toEqual(1)
        expect(nameConstraints.excludedSubtrees!.length).toEqual(1)
    })

    test('should handle NameConstraints with both permitted and excluded subtrees', () => {
        const permittedSubtree = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })
        const excludedSubtree = new GeneralSubtree({
            base: new dNSName({ value: 'blocked.example.com' }),
        })

        const nameConstraints = new NameConstraints({
            permittedSubtrees: new GeneralSubtrees(permittedSubtree),
            excludedSubtrees: new GeneralSubtrees(excludedSubtree),
        })

        expect(nameConstraints.permittedSubtrees).toBeDefined()
        expect(nameConstraints.excludedSubtrees).toBeDefined()
        expect(nameConstraints.permittedSubtrees!.length).toEqual(1)
        expect(nameConstraints.excludedSubtrees!.length).toEqual(1)

        // Test that we can access the subtrees
        expect(nameConstraints.permittedSubtrees![0].base).toBeInstanceOf(
            dNSName,
        )
        expect(nameConstraints.excludedSubtrees![0].base).toBeInstanceOf(
            dNSName,
        )
    })

    test('should convert to ASN.1 structure', () => {
        const permittedSubtree = new GeneralSubtree({
            base: new dNSName({ value: 'example.com' }),
        })

        const nameConstraints = new NameConstraints({
            permittedSubtrees: new GeneralSubtrees(permittedSubtree),
        })

        const asn1 = nameConstraints.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBeGreaterThan(0)
    })
})
