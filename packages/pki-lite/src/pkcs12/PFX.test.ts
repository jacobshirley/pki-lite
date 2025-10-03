import { describe, it, expect } from 'vitest'
import { PFX } from './PFX.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'
import { MacData } from './MacData.js'
import { DigestInfo } from './DigestInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { AuthenticatedSafe } from './AuthenticatedSafe.js'
import { OIDs } from '../core/OIDs.js'

describe('PFX', () => {
    it('encodes and decodes a minimal PFX', () => {
        const authSafe = new ContentInfo({
            contentType: '1.2.840.113549.1.7.1', // data
            content: new OctetString({ bytes: new Uint8Array([1, 2, 3]) }),
        })
        const pfx = new PFX({ authSafe })
        const der = pfx.toDer()
        const decoded = PFX.fromDer(der)
        expect(decoded.version).toEqual(3)
        expect(decoded.authSafe.contentType.value).toEqual(
            '1.2.840.113549.1.7.1',
        )
        // decoded.authSafe.content is an Any object; check its .derBytes
        expect(
            decoded.authSafe.content?.parseAs(OctetString).bytes ?? [],
        ).toEqual(new Uint8Array([1, 2, 3]))
    })

    it('encodes and decodes with MacData', () => {
        const authSafe = new ContentInfo({
            contentType: '1.2.840.113549.1.7.1',
            content: new Uint8Array([1, 2, 3]),
        })
        const mac = new DigestInfo({
            digestAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.3.14.3.2.26',
            }),
            digest: new OctetString({ bytes: new Uint8Array([1, 2, 3]) }),
        })
        const macSalt = new OctetString({ bytes: new Uint8Array([4, 5, 6]) })
        const macData = new MacData({ mac, macSalt, iterations: 2048 })
        const pfx = new PFX({ authSafe, macData })
        const der = pfx.toDer()
        const decoded = PFX.fromDer(der)
        expect(decoded.macData?.iterations).toEqual(2048)
        expect(Array.from(decoded.macData?.macSalt.bytes ?? [])).toEqual([
            4, 5, 6,
        ])
    })

    it('encodes and decodes a simple data-only PFX', () => {
        // Build AuthenticatedSafe as a single ContentInfo of type data, containing an empty OCTET STRING
        const dataContent = new ContentInfo({
            contentType: OIDs.PKCS7.DATA,
            content: new OctetString({ bytes: new Uint8Array([]) }),
        })

        const pfx = new PFX({
            authSafe: new ContentInfo({
                contentType: OIDs.PKCS7.DATA,
                content: new OctetString({
                    bytes: new AuthenticatedSafe(dataContent).toDer(),
                }),
            }),
        })

        const der = pfx.toDer()
        const decoded = PFX.fromDer(der)
        expect(decoded.version).toEqual(3)
        expect(decoded.macData).toBeUndefined()
        expect(decoded.authSafe).toBeInstanceOf(ContentInfo)
    })
})
