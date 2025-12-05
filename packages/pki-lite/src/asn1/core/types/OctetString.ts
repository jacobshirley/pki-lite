/**
 * ASN.1 Octet String type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export class OctetString extends BaseBlock {
    static override NAME = 'OCTET STRING'

    constructor(params: BaseBlockParams = {}) {
        super({
            ...params,
            tagNumber: TagNumber.OCTET_STRING,
            isConstructed: false,
        })
    }

    override toString(): string {
        if (this._valueHex.length <= 64) {
            const hex = Array.from(this._valueHex)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('')
            return `OCTET STRING : ${hex}`
        }
        return `OCTET STRING : ${this._valueHex.length} bytes`
    }
}

// Alias for backwards compatibility
export { OctetString as Asn1OctetString }
