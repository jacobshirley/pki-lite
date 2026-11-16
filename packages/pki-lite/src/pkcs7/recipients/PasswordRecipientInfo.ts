import {
    Asn1Node,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { CMSVersion } from '../CMSVersion.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag } from '../../core/tagging.js'

/**
 * Represents a PasswordRecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * PasswordRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,   -- always set to 0
 *   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 * ```
 */
export class PasswordRecipientInfo extends PkiBase<PasswordRecipientInfo> {
    version: CMSVersion
    keyDerivationAlgorithm?: AlgorithmIdentifier
    keyEncryptionAlgorithm: AlgorithmIdentifier
    encryptedKey: Uint8Array<ArrayBuffer>

    /**
     * Creates a new PasswordRecipientInfo instance.
     */
    constructor(options: {
        version?: CMSVersion
        keyEncryptionAlgorithm: AlgorithmIdentifier
        encryptedKey: Uint8Array<ArrayBuffer>
        keyDerivationAlgorithm?: AlgorithmIdentifier
    }) {
        super()

        const {
            version,
            keyEncryptionAlgorithm,
            encryptedKey,
            keyDerivationAlgorithm,
        } = options

        this.version = version ?? 0
        this.keyDerivationAlgorithm = keyDerivationAlgorithm
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        this.encryptedKey = encryptedKey
    }

    /**
     * Converts the PasswordRecipientInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [der.integer(this.version)]

        // keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier: the algorithm's
        // OID and parameters sit directly inside the [0]
        if (this.keyDerivationAlgorithm) {
            values.push(implicitTag(this.keyDerivationAlgorithm.toAsn1(), 0))
        }

        // Add keyEncryptionAlgorithm and encryptedKey
        values.push(
            this.keyEncryptionAlgorithm.toAsn1(),
            der.octetString(this.encryptedKey),
        )

        return der.sequence(values)
    }

    /**
     * Creates a PasswordRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): PasswordRecipientInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for PasswordRecipientInfo',
            )
        }

        const values = asn1.children
        if (values.length < 3 || values.length > 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 3-4 elements, got ${values.length}`,
            )
        }

        // Check version
        if (!values[0]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = der.readNumber(values[0])
        if (version !== CMSVersion.v0) {
            throw new Asn1ParseError(
                `Invalid version: expected 0, got ${version}`,
            )
        }

        let currentIndex = 1
        let keyDerivationAlgorithm: AlgorithmIdentifier | undefined = undefined

        // Check for keyDerivationAlgorithm (optional)
        if (
            values.length > 3 &&
            values[currentIndex]?.constructed &&
            values[currentIndex].tagClass === TagClass.Context &&
            values[currentIndex].tag === 0
        ) {
            const constructed = values[currentIndex]
            const [first] = constructed.children
            // Earlier versions of this library wrapped the SEQUENCE in an explicit [0]
            keyDerivationAlgorithm = AlgorithmIdentifier.fromAsn1(
                constructed.children.length === 1 &&
                    first.is(UniversalTag.Sequence)
                    ? first
                    : // [0] IMPLICIT AlgorithmIdentifier: its fields are the children
                      der.sequence(constructed.children),
            )
            currentIndex++
        }

        // Extract keyEncryptionAlgorithm
        const keyEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(
            values[currentIndex],
        )
        currentIndex++

        // Extract encryptedKey
        if (!values[currentIndex]?.is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }

        const octetString = values[currentIndex]
        const encryptedKey = octetString.bytes()

        return new PasswordRecipientInfo({
            version,
            keyEncryptionAlgorithm,
            encryptedKey,
            keyDerivationAlgorithm,
        })
    }
}
