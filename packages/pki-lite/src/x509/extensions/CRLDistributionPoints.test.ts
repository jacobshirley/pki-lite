import { describe, it, expect } from 'vitest'
import { CRLDistributionPoints } from './CRLDistributionPoints.js'
import { DistributionPoint } from './CRLDistributionPoints.js'
import {
    GeneralNames,
    dNSName,
    uniformResourceIdentifier,
} from '../GeneralName.js'
import { der, derToAsn1 } from '../../core/PkiBase.js'
import { ReasonFlags } from '../ReasonFlags.js'

function makeGeneralNames(uri: string) {
    return new GeneralNames(new uniformResourceIdentifier({ value: uri }))
}

describe('CRLDistributionPoints', () => {
    it('should encode and decode ASN.1 correctly', () => {
        const dp1 = new DistributionPoint({
            distributionPoint: makeGeneralNames('http://crl1.example.com'),
        })
        const dp2 = new DistributionPoint({
            distributionPoint: makeGeneralNames('http://crl2.example.com'),
        })
        const crldp = new CRLDistributionPoints(dp1, dp2)
        const asn1 = crldp.toAsn1()
        const decoded = CRLDistributionPoints.fromAsn1(asn1)
        expect(decoded.length).toEqual(2)
        expect(
            (decoded[0].distributionPoint as GeneralNames)[0].toString(),
        ).toEqual('http://crl1.example.com')
        expect(
            (decoded[1].distributionPoint as GeneralNames)[0].toString(),
        ).toEqual('http://crl2.example.com')
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() => CRLDistributionPoints.fromAsn1(der.nullValue())).toThrow(
            'Invalid ASN.1 structure for CRLDistributionPoints',
        )
    })

    it('should decode a single DistributionPoint', () => {
        const dp = new DistributionPoint({
            distributionPoint: makeGeneralNames('http://crl.example.com'),
        })
        const crldp = new CRLDistributionPoints(dp)
        const asn1 = crldp.toAsn1()
        const decoded = CRLDistributionPoints.fromAsn1(asn1)
        expect(decoded.length).toEqual(1)
        expect(
            (decoded[0].distributionPoint as GeneralNames)[0].toString(),
        ).toEqual('http://crl.example.com')
    })

    describe('encoding (RFC 5280, IMPLICIT TAGS)', () => {
        const toHex = (b: Uint8Array) =>
            Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
        const fromHex = (hex: string) =>
            new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)))

        // `crlDistributionPoints=URI:http://example.com/a.crl` as written by OpenSSL:
        // SEQUENCE { SEQUENCE { [0] { [0] { [6] "http://example.com/a.crl" } } } }
        const opensslDer =
            '3020301ea01ca01a8618687474703a2f2f6578616d706c652e636f6d2f612e63726c'

        it('matches the DER OpenSSL writes for a URI distribution point', () => {
            const crldp = new CRLDistributionPoints(
                new DistributionPoint({
                    distributionPoint: new GeneralNames(
                        new uniformResourceIdentifier({
                            value: 'http://example.com/a.crl',
                        }),
                    ),
                }),
            )
            expect(toHex(crldp.toDer())).toBe(opensslDer)
        })

        it('parses and re-encodes the DER OpenSSL writes', () => {
            const parsed = CRLDistributionPoints.fromAsn1(
                derToAsn1(fromHex(opensslDer)),
            )
            expect(parsed.length).toBe(1)
            expect(toHex(parsed.toDer())).toBe(opensslDer)
        })

        it('round-trips reasons (primitive [1]) and cRLIssuer ([2] GeneralNames)', () => {
            const dp = new DistributionPoint({
                distributionPoint: new GeneralNames(
                    new uniformResourceIdentifier({ value: 'http://a/b.crl' }),
                ),
                reasons: new ReasonFlags({
                    keyCompromise: true,
                    cACompromise: true,
                }),
                cRLIssuer: new GeneralNames(
                    new dNSName({ value: 'ca.example' }),
                ),
            })
            const encoded = dp.toDer()
            const parsed = DistributionPoint.fromAsn1(derToAsn1(encoded))
            expect(toHex(parsed.toDer())).toBe(toHex(encoded))
            expect(parsed.reasons?.keyCompromise).toBe(true)
            expect(parsed.cRLIssuer?.length).toBe(1)
        })
    })
})
