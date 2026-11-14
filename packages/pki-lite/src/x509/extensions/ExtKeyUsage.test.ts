import { describe, expect, test } from 'vitest'
import { ExtKeyUsage } from './ExtKeyUsage.js'
import { derToAsn1 } from '../../core/PkiBase.js'

describe('ExtKeyUsage', () => {
    test('create maps common names to OIDs and keeps OIDs', () => {
        const eku = ExtKeyUsage.create({
            serverAuth: true,
            clientAuth: false,
            '1.2.3.4': true,
        })
        expect(eku.map((oid) => oid.value)).toEqual([
            '1.3.6.1.5.5.7.3.1',
            '1.2.3.4',
        ])
    })

    test('round-trips through DER', () => {
        const eku = ExtKeyUsage.create({ codeSigning: true, ocspSigning: true })
        const parsed = ExtKeyUsage.fromAsn1(derToAsn1(eku.toDer()))
        expect(parsed.toDer()).toEqual(eku.toDer())
        expect(parsed.map((oid) => oid.value)).toEqual([
            '1.3.6.1.5.5.7.3.3',
            '1.3.6.1.5.5.7.3.9',
        ])
    })

    test('oidOf: common names and OIDs', () => {
        expect(ExtKeyUsage.oidOf('serverAuth')).toBe('1.3.6.1.5.5.7.3.1')
        expect(ExtKeyUsage.oidOf('ocspSigning')).toBe('1.3.6.1.5.5.7.3.9')
        expect(ExtKeyUsage.oidOf('1.2.3.4')).toBe('1.2.3.4')
    })
})
