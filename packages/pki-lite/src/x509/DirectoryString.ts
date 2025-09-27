import { BMPString } from '../asn1/BMPString.js'
import { PrintableString } from '../asn1/PrintableString.js'
import { TeletexString } from '../asn1/TeletexString.js'
import { UniversalString } from '../asn1/UniversalString.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { Asn1BaseBlock, asn1js, Choice } from '../core/PkiBase.js'
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
    fromAsn1(asn1: Asn1BaseBlock) {
        if (asn1 instanceof asn1js.TeletexString)
            return new TeletexString({ value: asn1.valueBlock.value })
        if (asn1 instanceof asn1js.PrintableString)
            return new PrintableString({ value: asn1.valueBlock.value })
        if (asn1 instanceof asn1js.UniversalString)
            return new UniversalString({ value: asn1.valueBlock.value })
        if (asn1 instanceof asn1js.Utf8String)
            return new UTF8String({ value: asn1.valueBlock.value })
        if (asn1 instanceof asn1js.BmpString)
            return new BMPString({ value: asn1.valueBlock.value })
        throw new Asn1ParseError('Invalid DirectoryString ASN.1 structure')
    },
    toAsn1(value: DirectoryString) {
        return value.toAsn1()
    },
})
