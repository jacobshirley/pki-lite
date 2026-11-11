import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { OIDs } from '../core/OIDs.js'
import {
    Asn1Any,
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    ObjectIdentifierString,
    PkiBase,
    PkiSequence,
    PkiSet,
} from '../core/PkiBase.js'
import {
    AccessDescription,
    AuthorityInfoAccess,
} from './extensions/AuthorityInfoAccess.js'
import { BasicConstraints } from './extensions/BasicConstraints.js'
import { AuthorityKeyIdentifier } from './extensions/AuthorityKeyIdentifier.js'
import { KeyIdentifier } from '../pkcs7/recipients/KeyIdentifier.js'
import { ExtKeyCommonNames, ExtKeyUsage } from './extensions/ExtKeyUsage.js'
import { KeyUsage, KeyUsageOptions } from './extensions/KeyUsage.js'
import { SubjectAltName } from './extensions/SubjectAltName.js'
import { CertificatePolicies } from './extensions/CertificatePolicies.js'
import { InhibitAnyPolicy } from './extensions/InhibitAnyPolicy.js'
import { PolicyMapping, PolicyMappings } from './extensions/PolicyMappings.js'
import { PolicyConstraints } from './extensions/PolicyConstraints.js'
import { PolicyInformation } from './PolicyInformation.js'
import { GeneralName } from './GeneralName.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a CRL extension.
 *
 * @asn
 * ```asn
 * Extension  ::=  SEQUENCE  {
 *      extnID      OBJECT IDENTIFIER,
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING
 * }
 * ```
 */
export class Extension extends PkiBase<Extension> {
    extnID: ObjectIdentifier
    critical: boolean
    extnValue: OctetString

    constructor(options: {
        extnID: ObjectIdentifierString
        critical?: boolean
        extnValue: Asn1Any
    }) {
        super()

        const { extnID, critical = false, extnValue } = options

        this.extnID = new ObjectIdentifier({ value: extnID })
        this.critical = critical
        this.extnValue =
            extnValue instanceof PkiBase ||
            extnValue instanceof PkiSequence ||
            extnValue instanceof PkiSet
                ? new OctetString({ bytes: extnValue.toDer() })
                : extnValue instanceof OctetString
                  ? extnValue
                  : new OctetString({
                        bytes: new Any({ derBytes: extnValue }).toDer(),
                    })
    }

    /**
     * Converts the extension to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []

        values.push(this.extnID.toAsn1())

        if (this.critical) {
            values.push(new asn1js.Boolean({ value: true }))
        }

        values.push(this.extnValue.toAsn1())

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates an Extension from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns An Extension
     */
    static fromAsn1(asn1: asn1js.BaseBlock): Extension {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('Expected Sequence')
        }

        if (
            asn1.valueBlock.value.length < 2 ||
            asn1.valueBlock.value.length > 3
        ) {
            throw new Asn1ParseError(
                'Expected 2 or 3 elements in Extension sequence',
            )
        }

        const extnIDBlock = asn1.valueBlock.value[0]

        if (!(extnIDBlock instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError('Expected ObjectIdentifier for extnID')
        }

        const extnID = extnIDBlock.valueBlock
            .toString()
            .replace('OBJECT IDENTIFIER : ', '')

        let critical = false
        let valueIndex = 1

        // If there are 3 elements, the second one is the critical flag
        if (asn1.valueBlock.value.length === 3) {
            const criticalBlock = asn1.valueBlock.value[1]
            if (!(criticalBlock instanceof asn1js.Boolean)) {
                throw new Asn1ParseError('Expected Boolean for critical')
            }
            critical = criticalBlock.valueBlock.value
            valueIndex = 2
        }

        const extnValueBlock = asn1.valueBlock.value[valueIndex]
        if (!(extnValueBlock instanceof asn1js.OctetString)) {
            throw new Asn1ParseError('Expected OctetString for extnValue')
        }

        const extnValue = new Uint8Array(extnValueBlock.valueBlock.valueHexView)

        return new Extension({
            extnID,
            critical,
            extnValue,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): Extension {
        return Extension.fromAsn1(derToAsn1(der))
    }

    static keyUsage(options?: KeyUsageOptions): Extension {
        const keyUsage = new KeyUsage(options || {})
        return new Extension({
            extnID: OIDs.EXTENSION.KEY_USAGE,
            critical: true,
            extnValue: keyUsage,
        })
    }

    static authorityKeyIdentifier(
        keyIdentifier: Uint8Array<ArrayBuffer>,
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] ... }, not a bare
            // OCTET STRING (that is the Subject Key Identifier's form)
            extnValue: new AuthorityKeyIdentifier({
                keyIdentifier: new KeyIdentifier({ bytes: keyIdentifier }),
            }),
        })
    }

    static subjectKeyIdentifier(
        keyIdentifier: Uint8Array<ArrayBuffer> | OctetString,
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extnValue: new OctetString({ bytes: keyIdentifier }),
        })
    }

    static basicConstraints(
        options:
            | {
                  cA: boolean
                  pathLenConstraint?: number
              }
            | BasicConstraints,
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.BASIC_CONSTRAINTS,
            critical: true,
            extnValue: new BasicConstraints(options),
        })
    }

    static certificatePolicies(
        policies: (string | PolicyInformation)[],
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.CERTIFICATE_POLICIES,
            critical: false,
            extnValue: new CertificatePolicies(
                ...policies.map((policy) =>
                    policy instanceof PolicyInformation
                        ? policy
                        : new PolicyInformation({ policyIdentifier: policy }),
                ),
            ),
        })
    }

    static policyMappings(
        mappings: (
            | PolicyMapping
            | {
                  issuerDomainPolicy: ObjectIdentifierString
                  subjectDomainPolicy: ObjectIdentifierString
              }
        )[],
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.POLICY_MAPPINGS,
            critical: false,
            extnValue: new PolicyMappings(
                ...mappings.map((mapping) =>
                    mapping instanceof PolicyMapping
                        ? mapping
                        : new PolicyMapping(mapping),
                ),
            ),
        })
    }

    static policyConstraints(options: {
        requireExplicitPolicy?: number
        inhibitPolicyMapping?: number
    }): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.POLICY_CONSTRAINTS,
            critical: true,
            extnValue: new PolicyConstraints(options),
        })
    }

    static inhibitAnyPolicy(skipCerts: number): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.INHIBIT_ANY_POLICY,
            critical: true,
            extnValue: new InhibitAnyPolicy({ skipCerts }),
        })
    }

    static subjectAltName(altNames: GeneralName[]): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.SUBJECT_ALT_NAME,
            critical: false,
            extnValue: new SubjectAltName(...altNames),
        })
    }

    static authorityInfoAccess(
        accessDescriptions:
            | {
                  accessMethod: ObjectIdentifierString
                  accessLocation: GeneralName
              }[]
            | AuthorityInfoAccess,
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.AUTHORITY_INFO_ACCESS,
            critical: false,
            extnValue:
                accessDescriptions instanceof AuthorityInfoAccess
                    ? accessDescriptions
                    : new AuthorityInfoAccess(
                          ...accessDescriptions.map(
                              (ad) => new AccessDescription(ad),
                          ),
                      ),
        })
    }

    static extendedKeyUsage(
        options:
            | ({
                  [key in ExtKeyCommonNames]?: boolean
              } & {
                  [oid: string]: boolean
              })
            | ExtKeyUsage,
    ): Extension {
        return new Extension({
            extnID: OIDs.EXTENSION.EXTENDED_KEY_USAGE,
            critical: false,
            extnValue:
                options instanceof ExtKeyUsage
                    ? options
                    : ExtKeyUsage.create(options),
        })
    }

    /**
     * Alias for {@link Extension.extendedKeyUsage}
     */
    static extKeyUsage = Extension.extendedKeyUsage
}
