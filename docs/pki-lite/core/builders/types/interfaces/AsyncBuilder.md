[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/types](../README.md) / AsyncBuilder

# Interface: AsyncBuilder\<T\>

Interface for asynchronous builder pattern implementations.

Some builders require asynchronous operations during construction,
such as cryptographic operations, network requests, or file I/O.
This interface defines the contract for such builders.

## Example

```typescript
class SignedDataBuilder implements AsyncBuilder<SignedData> {
    private data: Uint8Array
    private signers: Signer[] = []

    setData(data: Uint8Array): this {
        this.data = data
        return this
    }

    addSigner(signer: Signer): this {
        this.signers.push(signer)
        return this
    }

    async build(): Promise<SignedData> {
        // Perform async cryptographic operations
        const signatures = await this.computeSignatures()
        return new SignedData(this.data, signatures)
    }
}

const signedData = await new SignedDataBuilder()
    .setData(documentBytes)
    .addSigner(signer)
    .build()
```

## Type Parameters

### T

`T`

The type of object being built

## Methods

### build()

> **build**(): `Promise`\<`T`\>

Builds and returns the constructed object asynchronously.

#### Returns

`Promise`\<`T`\>

Promise resolving to the constructed object of type T
