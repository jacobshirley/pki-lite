/**
 * Utility functions for PKI operations
 */

/**
 * Pads a Uint8Array<ArrayBuffer> to the specified length by adding zeros to the left.
 * If the array is already at or exceeds the target length, it is returned as-is.
 *
 * @param array The array to pad
 * @param targetLength The desired length
 * @returns A new Uint8Array padded to the target length
 */
export function padUint8Array(
    array: Uint8Array<ArrayBuffer>,
    targetLength: number,
): Uint8Array<ArrayBuffer> {
    if (array.length >= targetLength) {
        return array
    }

    const result = new Uint8Array(targetLength)
    // Copy the original array to the right side (end) of the new array
    result.set(array, targetLength - array.length)
    return result
}

/**
 * Converts a hex string to a Uint8Array<ArrayBuffer>
 *
 * @param hex The hex string to convert (can optionally start with '0x')
 * @returns A Uint8Array<ArrayBuffer> containing the bytes represented by the hex string
 */
export function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
    // Remove 0x prefix if present
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex

    // Handle odd-length hex strings by padding with a leading zero
    const paddedHex = cleanHex.length % 2 === 0 ? cleanHex : '0' + cleanHex

    const bytes = new Uint8Array(paddedHex.length / 2)
    for (let i = 0; i < paddedHex.length; i += 2) {
        bytes[i / 2] = parseInt(paddedHex.substr(i, 2), 16)
    }
    return bytes
}

/**
 * Converts a Uint8Array<ArrayBuffer> to a hex string
 *
 * @param bytes The Uint8Array<ArrayBuffer> to convert
 * @param prefix Whether to include the '0x' prefix (default: false)
 * @returns A hex string representation of the Uint8Array<ArrayBuffer>
 */
export function uint8ArrayToHex(
    bytes: Uint8Array<ArrayBuffer>,
    prefix = false,
): string {
    const hex = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

    return prefix ? '0x' + hex : hex
}
