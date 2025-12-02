/**
 * ASN.1 Null type
 */

import { BaseBlock } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

class NullClass extends BaseBlock {
    static override NAME = 'NULL'

    constructor() {
        super({
            tagNumber: TagNumber.NULL,
            isConstructed: false,
            valueHex: new Uint8Array(0),
        })
    }

    override toString(): string {
        return 'NULL'
    }
}

// Export with name that matches asn1js
export { NullClass as Null }
// Alias for backwards compatibility
export { NullClass as Asn1Null }
