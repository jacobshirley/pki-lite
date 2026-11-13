import { describe, expect, test } from 'vitest'
import { IssuingDistributionPoint } from './IssuingDistributionPoint.js'
import { CertificateList } from '../CertificateList.js'
import { ReasonFlags } from '../ReasonFlags.js'
import { derToAsn1 } from '../../core/PkiBase.js'
import { OIDs } from '../../core/OIDs.js'
import { GeneralNames } from '../GeneralName.js'
import { pkitsFiles } from '../../../test-fixtures/pkits/pkits.js'

/** The issuingDistributionPoint extension of a NIST PKITS CRL, and its DER */
const idpOf = (name: string) => {
    const crl = CertificateList.fromDer(
        Uint8Array.from(atob(pkitsFiles[name]), (c) => c.charCodeAt(0)),
    )
    const extension = crl.tbsCertList.extensions!.find(
        (ext) => ext.extnID.value === OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
    )!
    return {
        der: extension.extnValue.bytes,
        idp: IssuingDistributionPoint.fromAsn1(
            derToAsn1(extension.extnValue.bytes),
        ),
    }
}

describe('IssuingDistributionPoint', () => {
    test.each([
        ['onlyContainsUserCertsCACRL', { onlyContainsUserCerts: true }],
        ['onlyContainsCACertsCACRL', { onlyContainsCACerts: true }],
        [
            'onlyContainsAttributeCertsCACRL',
            { onlyContainsAttributeCerts: true },
        ],
        ['indirectCRLCA1CRL', { indirectCRL: true }],
    ])('parses the flags of %s and re-encodes it exactly', (name, flags) => {
        const { der, idp } = idpOf(name)
        expect({
            onlyContainsUserCerts: idp.onlyContainsUserCerts,
            onlyContainsCACerts: idp.onlyContainsCACerts,
            onlyContainsAttributeCerts: idp.onlyContainsAttributeCerts,
            indirectCRL: idp.indirectCRL,
        }).toEqual({
            onlyContainsUserCerts: false,
            onlyContainsCACerts: false,
            onlyContainsAttributeCerts: false,
            indirectCRL: false,
            ...flags,
        })
        expect(idp.toDer()).toEqual(der)
    })

    test('parses onlySomeReasons', () => {
        const { der, idp } = idpOf('onlySomeReasonsCA1compromiseCRL')
        expect(idp.onlySomeReasons?.keyCompromise).toBe(true)
        expect(idp.onlySomeReasons?.cACompromise).toBe(true)
        expect(idp.onlySomeReasons?.superseded).toBe(false)
        expect(idp.toDer()).toEqual(der)
    })

    test('parses a distribution point name', () => {
        const { der, idp } = idpOf('distributionPoint1CACRL')
        expect(idp.distributionPoint).toBeInstanceOf(GeneralNames)
        expect(idp.toDer()).toEqual(der)
    })

    test('leaves DEFAULT FALSE flags out of the encoding', () => {
        expect(new IssuingDistributionPoint().toDer()).toEqual(
            new Uint8Array([0x30, 0x00]),
        )
        const idp = new IssuingDistributionPoint({
            onlyContainsCACerts: true,
            onlySomeReasons: new ReasonFlags({ keyCompromise: true }),
        })
        const parsed = IssuingDistributionPoint.fromAsn1(derToAsn1(idp.toDer()))
        expect(parsed.onlyContainsCACerts).toBe(true)
        expect(parsed.onlyContainsUserCerts).toBe(false)
        expect(parsed.onlySomeReasons?.keyCompromise).toBe(true)
    })

    test('rejects a structure that is not a SEQUENCE', () => {
        expect(() =>
            IssuingDistributionPoint.fromAsn1(
                derToAsn1(new Uint8Array([0x05, 0x00])),
            ),
        ).toThrow('IssuingDistributionPoint')
    })
})
