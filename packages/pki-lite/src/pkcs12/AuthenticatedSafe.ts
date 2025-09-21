import { ContentInfo } from '../pkcs7/ContentInfo.js'
import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    PkiSequence,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { SafeBag } from './SafeBag.js'
import { OIDs } from '../core/OIDs.js'
import { SafeContents } from './SafeContents.js'
import { EncryptedData } from '../pkcs7/EncryptedData.js'

/**
 * Represents the AuthenticatedSafe structure described in PKCS#12 standard.
 *
 * @asn
 * ```asn
 * AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 * ```
 */
export class AuthenticatedSafe extends PkiSequence<ContentInfo> {
    static fromAsn1(asn1: Asn1BaseBlock): AuthenticatedSafe {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('AuthenticatedSafe: expected SEQUENCE')
        }
        const contents = asn1.valueBlock.value.map((x) =>
            ContentInfo.fromAsn1(x),
        )
        return new AuthenticatedSafe(...contents)
    }

    static fromDer(der: Uint8Array): AuthenticatedSafe {
        return AuthenticatedSafe.fromAsn1(derToAsn1(der))
    }

    async getBags(password: string | Uint8Array): Promise<SafeBag[]> {
        const bags: SafeBag[] = []
        for (const contentInfo of this) {
            if (contentInfo.contentType.is(OIDs.PKCS7.ENCRYPTED_DATA)) {
                // This means it is a SafeBag
                const encryptedData = contentInfo.parseContentAs(EncryptedData)
                if (
                    encryptedData.encryptedContentInfo.contentType.isNot(
                        OIDs.PKCS7.DATA,
                    )
                ) {
                    throw new Error(
                        `Unsupported encrypted contentType: ${encryptedData.encryptedContentInfo.contentType}`,
                    )
                }

                const safeBags =
                    await encryptedData.encryptedContentInfo.decryptAs(
                        password,
                        SafeContents,
                    )

                for (const bag of safeBags) {
                    bags.push(bag)
                }
            } else if (contentInfo.contentType.is(OIDs.PKCS7.DATA)) {
                const safeBags = contentInfo.parseContentAs(SafeContents)
                for (const bag of safeBags) {
                    bags.push(bag)
                }
            } else {
                throw new Error(
                    `Unsupported contentType in AuthenticatedSafe: ${contentInfo.contentType.friendlyName}`,
                )
            }
        }
        return bags
    }

    async getBagsByName(
        bagName: keyof typeof OIDs.PKCS12.BAGS,
        password: string | Uint8Array,
    ): Promise<SafeBag[]> {
        const bags = await this.getBags(password)
        const bagId = OIDs.PKCS12.BAGS[bagName]
        if (!bagId) {
            throw new Error(`Unknown bag name: ${bagName}`)
        }
        return bags.filter((bag) => bag.bagId.is(bagId))
    }
}
