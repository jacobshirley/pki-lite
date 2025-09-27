import { describe, it, expect } from 'vitest'
import { AuthorityInfoAccess } from './AuthorityInfoAccess.js'
import { AccessDescription } from './AuthorityInfoAccess.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { GeneralName, uniformResourceIdentifier } from '../GeneralName.js'
import { asn1js } from '../../core/PkiBase.js'

function makeAccessDescription() {
    return new AccessDescription({
        accessMethod: new ObjectIdentifier({ value: '1.3.6.1.5.5.7.48.1' }), // id-ad-ocsp
        accessLocation: new uniformResourceIdentifier({
            value: 'http://ocsp.example.com',
        }),
    })
}

describe('AuthorityInfoAccess', () => {
    it('should encode and decode ASN.1 correctly', () => {
        const ad1 = makeAccessDescription()
        const ad2 = new AccessDescription({
            accessMethod: new ObjectIdentifier({ value: '1.3.6.1.5.5.7.48.2' }), // id-ad-caIssuers
            accessLocation: new uniformResourceIdentifier({
                value: 'http://ca.example.com',
            }),
        })
        const aia = new AuthorityInfoAccess(ad1, ad2)
        const asn1 = aia.toAsn1()
        const decoded = AuthorityInfoAccess.fromAsn1(asn1)
        expect(decoded.length).toBe(2)
        expect(decoded[0].accessMethod.value).toBe('1.3.6.1.5.5.7.48.1')
        expect(decoded[0].accessLocation.toString()).toBe(
            'http://ocsp.example.com',
        )
        expect(decoded[1].accessMethod.value).toBe('1.3.6.1.5.5.7.48.2')
        expect(decoded[1].accessLocation.toString()).toBe(
            'http://ca.example.com',
        )
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() => AuthorityInfoAccess.fromAsn1(new asn1js.Null())).toThrow(
            'ASN.1 structure should be a sequence',
        )
    })

    it('should decode a single AccessDescription', () => {
        const ad = makeAccessDescription()
        const aia = new AuthorityInfoAccess(ad)
        const asn1 = aia.toAsn1()
        const decoded = AuthorityInfoAccess.fromAsn1(asn1)
        expect(decoded.length).toBe(1)
        expect(decoded[0].accessMethod.value).toBe('1.3.6.1.5.5.7.48.1')
        expect(decoded[0].accessLocation.toString()).toBe(
            'http://ocsp.example.com',
        )
    })
})
