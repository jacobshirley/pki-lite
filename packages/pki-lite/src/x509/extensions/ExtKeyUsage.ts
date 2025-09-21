import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { OIDs } from '../../core/OIDs.js'
import { Asn1BaseBlock, asn1js, PkiSequence } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

export type ExtKeyCommonNames =
    | 'serverAuth'
    | 'clientAuth'
    | 'codeSigning'
    | 'emailProtection'
    | 'timeStamping'
    | 'ocspSigning'

export class ExtKeyUsage extends PkiSequence<ObjectIdentifier> {
    static create(
        options: {
            [key in ExtKeyCommonNames]?: boolean
        } & {
            [oid: string]: boolean
        },
    ): ExtKeyUsage {
        const mapping: { [key in ExtKeyCommonNames]?: keyof typeof OIDs.EKU } =
            {
                serverAuth: 'SERVER_AUTH',
                clientAuth: 'CLIENT_AUTH',
                codeSigning: 'CODE_SIGNING',
                emailProtection: 'EMAIL_PROTECTION',
                timeStamping: 'TIME_STAMPING',
                ocspSigning: 'OCSP_SIGNING',
            }

        const extKeyUsage = new ExtKeyUsage()

        for (const [key, value] of Object.entries(options)) {
            if (value) {
                let oid =
                    OIDs.EKU[
                        mapping[
                            key as ExtKeyCommonNames
                        ] as keyof typeof OIDs.EKU
                    ] ?? key
                extKeyUsage.push(new ObjectIdentifier({ value: oid }))
            }
        }

        return extKeyUsage
    }

    static fromAsn1(asn1: Asn1BaseBlock): ExtKeyUsage {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE but got ' +
                    asn1.constructor.name,
            )
        }

        const extKeyUsage = new ExtKeyUsage()

        for (const oidAsn1 of asn1.valueBlock.value) {
            const oid = ObjectIdentifier.fromAsn1(oidAsn1)
            extKeyUsage.push(oid)
        }

        return extKeyUsage
    }

    toHumanString(): string {
        return this.map((oid) => OIDs.getOidFriendlyName(oid.value)).join(', ')
    }
}
