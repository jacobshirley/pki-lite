import { PkiLiteError } from './PkiLiteError.js'

export class UnsupportedCryptoAlgorithmError extends PkiLiteError {
    name = 'UnsupportedCryptoAlgorithmError'

    constructor(algorithm: string) {
        super(`The cryptographic algorithm "${algorithm}" is not supported.`)
    }
}
