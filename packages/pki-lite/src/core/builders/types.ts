/**
 * Interface for synchronous builder pattern implementations.
 *
 * Builders provide a fluent API for constructing complex objects step by step.
 * This interface defines the contract for builders that can complete their
 * construction synchronously.
 *
 * @template T The type of object being built
 *
 * @example
 * ```typescript
 * class SimpleDataBuilder implements Builder<SimpleData> {
 *     private data: string = ''
 *
 *     setData(data: string): this {
 *         this.data = data
 *         return this
 *     }
 *
 *     build(): SimpleData {
 *         return new SimpleData(this.data)
 *     }
 * }
 *
 * const result = new SimpleDataBuilder()
 *     .setData('Hello')
 *     .build()
 * ```
 */
export interface Builder<T> {
    /**
     * Builds and returns the constructed object.
     *
     * @returns The constructed object of type T
     */
    build(): T
}

/**
 * Interface for asynchronous builder pattern implementations.
 *
 * Some builders require asynchronous operations during construction,
 * such as cryptographic operations, network requests, or file I/O.
 * This interface defines the contract for such builders.
 *
 * @template T The type of object being built
 *
 * @example
 * ```typescript
 * class SignedDataBuilder implements AsyncBuilder<SignedData> {
 *     private data: Uint8Array
 *     private signers: Signer[] = []
 *
 *     setData(data: Uint8Array): this {
 *         this.data = data
 *         return this
 *     }
 *
 *     addSigner(signer: Signer): this {
 *         this.signers.push(signer)
 *         return this
 *     }
 *
 *     async build(): Promise<SignedData> {
 *         // Perform async cryptographic operations
 *         const signatures = await this.computeSignatures()
 *         return new SignedData(this.data, signatures)
 *     }
 * }
 *
 * const signedData = await new SignedDataBuilder()
 *     .setData(documentBytes)
 *     .addSigner(signer)
 *     .build()
 * ```
 */
export interface AsyncBuilder<T> {
    /**
     * Builds and returns the constructed object asynchronously.
     *
     * @returns Promise resolving to the constructed object of type T
     */
    build(): Promise<T>
}
