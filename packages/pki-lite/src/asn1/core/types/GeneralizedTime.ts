/**
 * ASN.1 Generalized Time type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface GeneralizedTimeParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
    valueDate?: Date
}

export class GeneralizedTime extends BaseBlock {
    static override NAME = 'GeneralizedTime'

    private _stringValue: string = ''
    private _dateValue: Date | null = null

    constructor(params: GeneralizedTimeParams = {}) {
        super({
            tagNumber: TagNumber.GENERALIZED_TIME,
            tagClass: params.tagClass,
            isConstructed: false,
        })

        if (params.valueDate) {
            this._dateValue = params.valueDate
            this._stringValue = this.dateToString(params.valueDate)
            this._valueHex = new TextEncoder().encode(this._stringValue)
        } else if (params.value !== undefined) {
            this._stringValue = params.value
            this._dateValue = this.parseDate(params.value)
            this._valueHex = new TextEncoder().encode(params.value)
        } else if (params.valueHex) {
            this._stringValue = new TextDecoder().decode(
                new Uint8Array(params.valueHex),
            )
            this._dateValue = this.parseDate(this._stringValue)
        }
    }

    private dateToString(date: Date): string {
        const year = date.getUTCFullYear().toString().padStart(4, '0')
        const month = (date.getUTCMonth() + 1).toString().padStart(2, '0')
        const day = date.getUTCDate().toString().padStart(2, '0')
        const hours = date.getUTCHours().toString().padStart(2, '0')
        const minutes = date.getUTCMinutes().toString().padStart(2, '0')
        const seconds = date.getUTCSeconds().toString().padStart(2, '0')

        return `${year}${month}${day}${hours}${minutes}${seconds}Z`
    }

    private parseDate(value: string): Date | null {
        // GeneralizedTime format: YYYYMMDDhhmmss[.fraction][Z|+hhmm|-hhmm]
        const match = value.match(
            /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?([Z+-])?(.+)?$/,
        )
        if (!match) return null

        const year = parseInt(match[1], 10)
        const month = parseInt(match[2], 10) - 1
        const day = parseInt(match[3], 10)
        const hours = parseInt(match[4], 10)
        const minutes = parseInt(match[5], 10)
        const seconds = match[6] ? parseInt(match[6], 10) : 0

        let milliseconds = 0
        if (match[7]) {
            const fraction = parseFloat(match[7])
            milliseconds = Math.round(fraction * 1000)
        }

        const date = new Date(
            Date.UTC(year, month, day, hours, minutes, seconds, milliseconds),
        )

        // Handle timezone offset
        if (match[8] && match[8] !== 'Z' && match[9]) {
            const tzSign = match[8] === '+' ? 1 : -1
            const tzHours = parseInt(match[9].substring(0, 2), 10)
            const tzMinutes = parseInt(match[9].substring(2, 4), 10)
            date.setUTCMinutes(
                date.getUTCMinutes() - tzSign * (tzHours * 60 + tzMinutes),
            )
        }

        return date
    }

    get value(): string {
        return this._stringValue
    }

    set value(val: string) {
        this._stringValue = val
        this._dateValue = this.parseDate(val)
        this._valueHex = new TextEncoder().encode(val)
    }

    override getValue(): string {
        return this._stringValue
    }

    toDate(): Date | null {
        return this._dateValue
    }

    fromDate(date: Date): void {
        this._dateValue = date
        this._stringValue = this.dateToString(date)
        this._valueHex = new TextEncoder().encode(this._stringValue)
    }

    override toString(): string {
        if (this._dateValue) {
            return `GeneralizedTime : ${this._dateValue.toISOString()}`
        }
        return `GeneralizedTime : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { GeneralizedTime as Asn1GeneralizedTime }
