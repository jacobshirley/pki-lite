/**
 * Custom ASN.1 DER implementation for pki-lite
 *
 * This module provides a lightweight replacement for asn1js with
 * compatibility for the existing codebase.
 */

// Core
import { BaseBlock as BaseBlockClass } from './BaseBlock.js'
export {
    BaseBlock,
    type BaseBlockParams,
    type BaseBlockJson,
} from './BaseBlock.js'
export { fromBER, type FromBerResult } from './parser.js'
export {
    TagClass,
    TagNumber,
    CONSTRUCTED_BIT,
    LONG_FORM_TAG,
    LENGTH_LONG_FORM_BIT,
    LENGTH_INDEFINITE,
} from './constants.js'

// Types - export with names matching asn1js for compatibility
export { Boolean, Asn1Boolean, type BooleanParams } from './types/Boolean.js'
export { Integer, Asn1Integer, type IntegerParams } from './types/Integer.js'
export { Enumerated, Asn1Enumerated } from './types/Enumerated.js'
export {
    BitString,
    Asn1BitString,
    type BitStringParams,
} from './types/BitString.js'
export { OctetString, Asn1OctetString } from './types/OctetString.js'
export { Null, Asn1Null } from './types/Null.js'
export {
    ObjectIdentifier,
    Asn1ObjectIdentifier,
    type ObjectIdentifierParams,
} from './types/ObjectIdentifier.js'
export {
    Sequence,
    Asn1Sequence,
    type SequenceParams,
} from './types/Sequence.js'
export { Set, Asn1Set, type SetParams } from './types/Set.js'
export {
    Utf8String,
    Asn1UTF8String,
    Asn1Utf8String,
    type Utf8StringParams,
} from './types/UTF8String.js'
export {
    PrintableString,
    Asn1PrintableString,
    type PrintableStringParams,
} from './types/PrintableString.js'
export {
    TeletexString,
    Asn1TeletexString,
    type TeletexStringParams,
} from './types/TeletexString.js'
export {
    IA5String,
    Asn1IA5String,
    type IA5StringParams,
} from './types/IA5String.js'
export { UTCTime, Asn1UTCTime, type UTCTimeParams } from './types/UTCTime.js'
export {
    GeneralizedTime,
    Asn1GeneralizedTime,
    type GeneralizedTimeParams,
} from './types/GeneralizedTime.js'
export {
    BmpString,
    Asn1BmpString,
    type BmpStringParams,
} from './types/BmpString.js'
export {
    UniversalString,
    Asn1UniversalString,
    type UniversalStringParams,
} from './types/UniversalString.js'
export {
    Constructed,
    Asn1Constructed,
    type ConstructedParams,
} from './types/Constructed.js'
export {
    Primitive,
    Asn1Primitive,
    type PrimitiveParams,
} from './types/Primitive.js'

// Type alias for compatibility with asn1js
export type AsnType = BaseBlockClass
