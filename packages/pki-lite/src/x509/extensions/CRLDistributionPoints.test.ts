import { describe, it, expect } from 'vitest'
import { CRLDistributionPoints } from './CRLDistributionPoints.js'
import { DistributionPoint } from './CRLDistributionPoints.js'
import { GeneralNames, uniformResourceIdentifier } from '../GeneralName.js'
import { asn1js } from '../../core/PkiBase.js'

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
        expect(() => CRLDistributionPoints.fromAsn1(new asn1js.Null())).toThrow(
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
})
