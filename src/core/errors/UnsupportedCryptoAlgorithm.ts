import { PkiLiteError } from './PkiLiteError.js'

export class UnsupportedCryptoAlgorithm extends PkiLiteError {
    name = 'UnsupportedCryptoAlgorithm'

    constructor(algorithm: string) {
        super(`The cryptographic algorithm "${algorithm}" is not supported.`)
    }
}
