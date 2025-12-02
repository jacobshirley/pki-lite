/**
 * ASN.1 DER Parser
 *
 * Parses DER-encoded ASN.1 data and returns the appropriate type.
 */

import { BaseBlock, BaseBlockParams } from './BaseBlock.js'
import {
    CONSTRUCTED_BIT,
    LENGTH_LONG_FORM_BIT,
    LONG_FORM_TAG,
    TagClass,
    TagNumber,
} from './constants.js'
import { Boolean as Asn1Boolean } from './types/Boolean.js'
import { Integer as Asn1Integer } from './types/Integer.js'
import { BitString as Asn1BitString } from './types/BitString.js'
import { OctetString as Asn1OctetString } from './types/OctetString.js'
import { Null as Asn1Null } from './types/Null.js'
import { ObjectIdentifier as Asn1ObjectIdentifier } from './types/ObjectIdentifier.js'
import { Sequence as Asn1Sequence } from './types/Sequence.js'
import { Set as Asn1Set } from './types/Set.js'
import { Utf8String as Asn1UTF8String } from './types/UTF8String.js'
import { PrintableString as Asn1PrintableString } from './types/PrintableString.js'
import { TeletexString as Asn1TeletexString } from './types/TeletexString.js'
import { IA5String as Asn1IA5String } from './types/IA5String.js'
import { UTCTime as Asn1UTCTime } from './types/UTCTime.js'
import { GeneralizedTime as Asn1GeneralizedTime } from './types/GeneralizedTime.js'
import { BmpString as Asn1BmpString } from './types/BmpString.js'
import { UniversalString as Asn1UniversalString } from './types/UniversalString.js'
import { Enumerated as Asn1Enumerated } from './types/Enumerated.js'
import { Constructed as Asn1Constructed } from './types/Constructed.js'
import { Primitive as Asn1Primitive } from './types/Primitive.js'

/**
 * Result of parsing ASN.1 data
 */
export interface FromBerResult {
    offset: number
    result: BaseBlock
}

/**
 * Decode a tag from buffer
 */
function decodeTag(
    buffer: Uint8Array,
    offset: number,
): {
    tagClass: number
    isConstructed: boolean
    tagNumber: number
    newOffset: number
} {
    if (offset >= buffer.length) {
        throw new Error('Unexpected end of buffer when reading tag')
    }

    const firstByte = buffer[offset]
    const tagClass = firstByte & 0xc0
    const isConstructed = (firstByte & CONSTRUCTED_BIT) !== 0

    let tagNumber = firstByte & 0x1f
    let newOffset = offset + 1

    // Long form tag
    if (tagNumber === LONG_FORM_TAG) {
        tagNumber = 0
        while (newOffset < buffer.length) {
            const byte = buffer[newOffset++]
            tagNumber = (tagNumber << 7) | (byte & 0x7f)
            if ((byte & 0x80) === 0) break
        }
    }

    return { tagClass, isConstructed, tagNumber, newOffset }
}

/**
 * Decode length from buffer
 */
function decodeLength(
    buffer: Uint8Array,
    offset: number,
): { length: number; newOffset: number } {
    if (offset >= buffer.length) {
        throw new Error('Unexpected end of buffer when reading length')
    }

    const firstByte = buffer[offset]

    // Short form
    if ((firstByte & LENGTH_LONG_FORM_BIT) === 0) {
        return { length: firstByte, newOffset: offset + 1 }
    }

    // Indefinite length (not supported in DER, but handle gracefully)
    if (firstByte === LENGTH_LONG_FORM_BIT) {
        throw new Error('Indefinite length encoding is not supported in DER')
    }

    // Long form
    const numBytes = firstByte & 0x7f
    if (offset + 1 + numBytes > buffer.length) {
        throw new Error('Unexpected end of buffer when reading length')
    }

    let length = 0
    for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | buffer[offset + 1 + i]
    }

    return { length, newOffset: offset + 1 + numBytes }
}

/**
 * Create an ASN.1 type from parsed parameters
 */
function createAsn1Type(params: {
    tagClass: number
    tagNumber: number
    isConstructed: boolean
    content: Uint8Array
    rawBytes: Uint8Array
}): BaseBlock {
    const { tagClass, tagNumber, isConstructed, content, rawBytes } = params

    // Context-specific or application tags
    if (tagClass !== TagClass.UNIVERSAL) {
        if (isConstructed) {
            // Parse nested content
            const children: BaseBlock[] = []
            let offset = 0
            while (offset < content.length) {
                const result = parseFromOffset(content, offset)
                children.push(result.result)
                offset = result.offset
            }
            const block = new Asn1Constructed({
                tagNumber,
                tagClass,
                value: children,
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        } else {
            const block = new Asn1Primitive({
                tagNumber,
                tagClass,
                valueHex: content,
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }
    }

    // Universal tags
    switch (tagNumber) {
        case TagNumber.BOOLEAN: {
            const block = new Asn1Boolean({
                value: content.length > 0 && content[0] !== 0,
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.INTEGER: {
            const block = new Asn1Integer({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.ENUMERATED: {
            const block = new Asn1Enumerated({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.BIT_STRING: {
            const block = new Asn1BitString({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.OCTET_STRING: {
            const block = new Asn1OctetString({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.NULL: {
            const block = new Asn1Null()
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.OBJECT_IDENTIFIER: {
            const block = new Asn1ObjectIdentifier({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.SEQUENCE: {
            const children: BaseBlock[] = []
            let offset = 0
            while (offset < content.length) {
                const result = parseFromOffset(content, offset)
                children.push(result.result)
                offset = result.offset
            }
            const block = new Asn1Sequence({ value: children })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.SET: {
            const children: BaseBlock[] = []
            let offset = 0
            while (offset < content.length) {
                const result = parseFromOffset(content, offset)
                children.push(result.result)
                offset = result.offset
            }
            const block = new Asn1Set({ value: children })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.UTF8_STRING: {
            const block = new Asn1UTF8String({
                value: new TextDecoder().decode(content),
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.PRINTABLE_STRING: {
            const block = new Asn1PrintableString({
                value: new TextDecoder().decode(content),
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.TELETEX_STRING: {
            const block = new Asn1TeletexString({
                value: new TextDecoder().decode(content),
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.IA5_STRING: {
            const block = new Asn1IA5String({
                value: new TextDecoder().decode(content),
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.UTC_TIME: {
            const block = new Asn1UTCTime({
                value: new TextDecoder().decode(content),
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.GENERALIZED_TIME: {
            const block = new Asn1GeneralizedTime({
                value: new TextDecoder().decode(content),
            })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.BMP_STRING: {
            const block = new Asn1BmpString({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        case TagNumber.UNIVERSAL_STRING: {
            const block = new Asn1UniversalString({ valueHex: content })
            ;(block as any)._valueBeforeDecodeView = rawBytes
            return block
        }

        default: {
            // Unknown tag - create a generic primitive or constructed
            if (isConstructed) {
                const children: BaseBlock[] = []
                let offset = 0
                while (offset < content.length) {
                    const result = parseFromOffset(content, offset)
                    children.push(result.result)
                    offset = result.offset
                }
                const block = new Asn1Constructed({
                    tagNumber,
                    tagClass,
                    value: children,
                })
                ;(block as any)._valueBeforeDecodeView = rawBytes
                return block
            } else {
                const block = new Asn1Primitive({
                    tagNumber,
                    tagClass,
                    valueHex: content,
                })
                ;(block as any)._valueBeforeDecodeView = rawBytes
                return block
            }
        }
    }
}

/**
 * Parse ASN.1 from a specific offset
 */
function parseFromOffset(
    buffer: Uint8Array,
    startOffset: number,
): FromBerResult {
    const {
        tagClass,
        isConstructed,
        tagNumber,
        newOffset: tagEnd,
    } = decodeTag(buffer, startOffset)
    const { length, newOffset: lengthEnd } = decodeLength(buffer, tagEnd)

    if (lengthEnd + length > buffer.length) {
        throw new Error('Content extends beyond buffer')
    }

    const content = buffer.slice(lengthEnd, lengthEnd + length)
    const rawBytes = buffer.slice(startOffset, lengthEnd + length)

    const result = createAsn1Type({
        tagClass,
        tagNumber,
        isConstructed,
        content,
        rawBytes,
    })

    return {
        offset: lengthEnd + length,
        result,
    }
}

/**
 * Parse ASN.1 DER/BER encoded data
 */
export function fromBER(inputBuffer: ArrayBuffer | Uint8Array): FromBerResult {
    const buffer =
        inputBuffer instanceof Uint8Array
            ? inputBuffer
            : new Uint8Array(inputBuffer)

    if (buffer.length === 0) {
        throw new Error('Empty input buffer')
    }

    return parseFromOffset(buffer, 0)
}
