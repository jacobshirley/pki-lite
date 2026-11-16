import { BMPString } from '../asn1/BMPString.js'
import { PrintableString } from '../asn1/PrintableString.js'
import { TeletexString } from '../asn1/TeletexString.js'
import { UniversalString } from '../asn1/UniversalString.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { Asn1Node, Choice, der, UniversalTag } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

export type DirectoryString =
    | TeletexString
    | PrintableString
    | UniversalString
    | UTF8String
    | BMPString
export const DirectoryString = Choice('DirectoryString', {
    teletexString: TeletexString,
    printableString: PrintableString,
    universalString: UniversalString,
    utf8String: UTF8String,
    bmpString: BMPString,
    fromAsn1(asn1: Asn1Node) {
        if (asn1.is(UniversalTag.TeletexString))
            return new TeletexString({ value: der.readString(asn1) })
        if (asn1.is(UniversalTag.PrintableString))
            return new PrintableString({ value: der.readString(asn1) })
        if (asn1.is(UniversalTag.UniversalString))
            return new UniversalString({ value: der.readString(asn1) })
        if (asn1.is(UniversalTag.UTF8String))
            return new UTF8String({ value: der.readString(asn1) })
        if (asn1.is(UniversalTag.BMPString))
            return new BMPString({ value: der.readString(asn1) })
        throw new Asn1ParseError('Invalid DirectoryString ASN.1 structure')
    },
    toAsn1(value: DirectoryString) {
        return value.toAsn1()
    },
})
