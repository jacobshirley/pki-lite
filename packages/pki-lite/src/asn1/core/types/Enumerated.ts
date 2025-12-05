/**
 * ASN.1 Enumerated type (similar to Integer)
 */

import { Integer, IntegerParams } from './Integer.js'
import { TagNumber } from '../constants.js'

export class Enumerated extends Integer {
    static override NAME = 'ENUMERATED'

    constructor(params: IntegerParams = {}) {
        super(params)
        this.tagNumber = TagNumber.ENUMERATED
    }

    override toString(): string {
        return `ENUMERATED : ${this.toDecimal()}`
    }
}

// Alias for backwards compatibility
export { Enumerated as Asn1Enumerated }
