[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/types](../README.md) / Builder

# Interface: Builder\<T\>

Interface for synchronous builder pattern implementations.

Builders provide a fluent API for constructing complex objects step by step.
This interface defines the contract for builders that can complete their
construction synchronously.

## Example

```typescript
class SimpleDataBuilder implements Builder<SimpleData> {
    private data: string = ''

    setData(data: string): this {
        this.data = data
        return this
    }

    build(): SimpleData {
        return new SimpleData(this.data)
    }
}

const result = new SimpleDataBuilder().setData('Hello').build()
```

## Type Parameters

### T

`T`

The type of object being built

## Methods

### build()

> **build**(): `T`

Builds and returns the constructed object.

#### Returns

`T`

The constructed object of type T
