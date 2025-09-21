import * as asn1js from 'asn1js'
import { Any } from '../asn1/Any.js'
export * as asn1js from 'asn1js'
import { Asn1ParseError } from './errors/Asn1ParseError.js'

// Fixes an issue where asn1js.Boolean.toString would return
// `BOOLEAN : getValue() {
//        return this.valueBlock.value;
//  }`
asn1js.Boolean.prototype.toString = function () {
    return `BOOLEAN: ${('' + this.getValue()).toUpperCase()}`
}

export type Asn1BaseBlock = asn1js.BaseBlock

// TODO
export type ToJson<T> = {
    [K in keyof T]: T[K] extends object ? ToJson<T[K]> : T[K]
}

export type ParseableAsn1<T> = {
    fromAsn1?(asn1: Asn1BaseBlock): T
    fromDer?(der: Uint8Array): T
}

/**
 * Represents a PKI object.
 */
export abstract class PkiBase<T extends object = any> {
    abstract toAsn1(): Asn1BaseBlock

    get pkiType(): string {
        return this.constructor.name
    }

    get pemHeader(): string {
        return this.pkiType.toUpperCase()
    }

    toJSON(): ToJson<T> {
        return JSON.parse(JSON.stringify(this)) as T
    }

    toString(): string {
        return `[${this.pkiType}] ${this.toAsn1().toString()}`
    }

    toHumanString(): string {
        // By default, just return the same as toString
        return this.toString()
    }

    toDer(): Uint8Array {
        return asn1ToDer(this.toAsn1())
    }

    toPem(): string {
        const der = this.toDer()
        const base64 = arrayToBase64(der)
        return `-----BEGIN ${this.pemHeader}-----\n${base64}\n-----END ${this.pemHeader}-----`
    }

    equals(other: PkiBase<any>): boolean {
        return this.toDer().toString() === other.toDer().toString()
    }

    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.toDer())
        } else if (type.fromAsn1) {
            return type.fromAsn1(this.toAsn1())
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }
}

export abstract class PkiArray<T extends PkiBase<any>> extends Array<T> {
    protected maxSize?: number

    push(...items: T[]): number {
        if (!this.maxSize) {
            return super.push(...items)
        }

        let newLen = this.length + items.length
        if (newLen > this.maxSize) {
            throw new Error(`Max size exceeded: ${this.maxSize}`)
        }
        return super.push(...items)
    }

    get pkiType(): string {
        return this.constructor.name
    }

    get pemHeader(): string {
        return this.pkiType.toUpperCase()
    }

    toJSON(): ToJson<T> {
        return JSON.parse(JSON.stringify(this)) as T
    }

    toString(): string {
        return `[${this.pkiType}] ${this.toAsn1().toString()}`
    }

    toDer(): Uint8Array {
        return asn1ToDer(this.toAsn1())
    }

    toPem(): string {
        const der = this.toDer()
        const base64 = arrayToBase64(der)
        return `-----BEGIN ${this.pemHeader}-----\n${base64}\n-----END ${this.pemHeader}-----`
    }

    abstract toAsn1(): Asn1BaseBlock
}

export class PkiSet<T extends PkiBase<any> = any> extends PkiArray<T> {
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Set({
            value: [...this].map((item) => item.toAsn1()),
        })
    }

    toDer(): Uint8Array {
        return asn1ToDer(this.toAsn1())
    }

    equals(other: PkiSet<T>): boolean {
        if (this.length !== other.length) {
            return false
        }

        for (let i = 0; i < this.length; i++) {
            if (!this[i].equals(other[i])) {
                return false
            }
        }

        return true
    }

    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.toDer())
        } else if (type.fromAsn1) {
            return type.fromAsn1(this.toAsn1())
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }

    toHumanString(): string {
        return this.map((child) => child.toHumanString()).join(', ')
    }
}

export class PkiSequence<T extends PkiBase<any> = any> extends PkiArray<T> {
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [...this].map((item) => item.toAsn1()),
        })
    }

    toDer(): Uint8Array {
        return asn1ToDer(this.toAsn1())
    }

    equals(other: PkiSequence<T>): boolean {
        if (this.length !== other.length) {
            return false
        }

        for (let i = 0; i < this.length; i++) {
            if (!this[i].equals(other[i])) {
                return false
            }
        }

        return true
    }

    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.toDer())
        } else if (type.fromAsn1) {
            return type.fromAsn1(this.toAsn1())
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }

    toHumanString(): string {
        return this.map((child) => child.toHumanString()).join(', ')
    }
}

export function asn1ToDer(value: Asn1BaseBlock): Uint8Array {
    return new Uint8Array(value.toBER(false))
}

export function derToAsn1(der: Uint8Array | ArrayBuffer): Asn1BaseBlock {
    return asn1js.fromBER(der).result
}

/**
 * Convert a Uint8Array to a base64 string in a browser-compatible way
 */
export function arrayToBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode.apply(null, Array.from(bytes)))
}

/**
 * Converts a base64 string to a Uint8Array (browser-compatible)
 */
export function base64ToArray(base64: string): Uint8Array {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

const hexChars = '0123456789ABCDEF'

export function bytesToHexBytes(bytes: Uint8Array): Uint8Array {
    const result = new Uint8Array(bytes.length * 2)

    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]
        result[i * 2] = hexChars.charCodeAt((byte >> 4) & 0x0f)
        result[i * 2 + 1] = hexChars.charCodeAt(byte & 0x0f)
    }

    return result
}

export function bytesToHexString(bytes: Uint8Array): string {
    let hex = ''
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]
        hex += hexChars.charAt((byte >> 4) & 0x0f)
        hex += hexChars.charAt(byte & 0x0f)
    }
    return hex
}

export function hexBytesToBytes(hex: Uint8Array): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(String.fromCharCode(hex[i], hex[i + 1]), 16)
    }
    return bytes
}

export function pemToDer(pem: string, name: string | string[]): Uint8Array {
    const names = Array.isArray(name) ? name : [name]

    for (const n of names) {
        const regex = new RegExp(
            `-----BEGIN ${n}-----([\\s\\S]+?)-----END ${n}-----`,
            'g',
        )
        const matches = [...pem.matchAll(regex)]
        if (matches.length > 1) {
            throw new Error('Multiple PEM blocks found; expected only one')
        }

        if (matches.length === 1) {
            const b64 = matches[0][1].replace(/\s+/g, '')
            return base64ToArray(b64)
        }
    }

    throw new Asn1ParseError('Invalid PEM format')
}

export function Choice<T>(name: string, choices: T): T {
    return {
        [Symbol.toStringTag]: name,
        ...choices,
    }
}

/**
 * Represents an object identifier (OID).
 */
export type ObjectIdentifierString = string | { toString(): string }

export type Asn1Any =
    | Uint8Array
    | Asn1BaseBlock
    | null
    | string
    | Any
    | PkiBase
    | number
    | boolean
