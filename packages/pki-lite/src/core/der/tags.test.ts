import { describe, expect, test } from 'vitest'
import { TagClass, UniversalTag } from './tags.js'

describe('tags', () => {
    test('tag classes are the identifier octet class bits', () => {
        expect(Object.values(TagClass)).toEqual([0, 1, 2, 3])
    })

    test('universal tag numbers match X.680', () => {
        expect(UniversalTag.Sequence).toBe(16)
        expect(UniversalTag.Set).toBe(17)
        expect(UniversalTag.BMPString).toBe(30)
        expect(new Set(Object.values(UniversalTag)).size).toBe(
            Object.keys(UniversalTag).length,
        )
    })
})
