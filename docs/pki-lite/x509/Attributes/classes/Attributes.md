[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/Attributes](../README.md) / Attributes

# Class: Attributes

Represents a set of attributes.

## Asn

```asn
Attributes ::= SET SIZE (1..MAX) OF Attribute
```

## Extends

- [`PkiSet`](../../../core/PkiBase/classes/PkiSet.md)\<[`Attribute`](../../Attribute/classes/Attribute.md)\>

## Extended by

- [`UnsignedAttributes`](../../../pkcs7/SignerInfo/classes/UnsignedAttributes.md)
- [`SignedAttributes`](../../../pkcs7/SignerInfo/classes/SignedAttributes.md)

## Indexable

\[`n`: `number`\]: [`Attribute`](../../Attribute/classes/Attribute.md)

## Constructors

### Constructor

> **new Attributes**(`arrayLength`): `Attributes`

#### Parameters

##### arrayLength

`number`

#### Returns

`Attributes`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`constructor`](../../../core/PkiBase/classes/PkiSet.md#constructor)

### Constructor

> **new Attributes**(...`items`): `Attributes`

#### Parameters

##### items

...[`Attribute`](../../Attribute/classes/Attribute.md)[]

#### Returns

`Attributes`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`constructor`](../../../core/PkiBase/classes/PkiSet.md#constructor)

## Properties

### \[unscopables\]

> `readonly` **\[unscopables\]**: `object`

Is an object whose properties have the value 'true'
when they will be absent when used in a 'with' statement.

#### Index Signature

\[`key`: `number`\]: `undefined` \| `boolean`

#### \[iterator\]?

> `optional` **\[iterator\]**: `boolean`

#### \[unscopables\]?

> `readonly` `optional` **\[unscopables\]**: `boolean`

Is an object whose properties have the value 'true'
when they will be absent when used in a 'with' statement.

#### at?

> `optional` **at**: `boolean`

#### concat?

> `optional` **concat**: `boolean`

#### copyWithin?

> `optional` **copyWithin**: `boolean`

#### entries?

> `optional` **entries**: `boolean`

#### every?

> `optional` **every**: `boolean`

#### fill?

> `optional` **fill**: `boolean`

#### filter?

> `optional` **filter**: `boolean`

#### find?

> `optional` **find**: `boolean`

#### findIndex?

> `optional` **findIndex**: `boolean`

#### findLast?

> `optional` **findLast**: `boolean`

#### findLastIndex?

> `optional` **findLastIndex**: `boolean`

#### flat?

> `optional` **flat**: `boolean`

#### flatMap?

> `optional` **flatMap**: `boolean`

#### forEach?

> `optional` **forEach**: `boolean`

#### includes?

> `optional` **includes**: `boolean`

#### indexOf?

> `optional` **indexOf**: `boolean`

#### join?

> `optional` **join**: `boolean`

#### keys?

> `optional` **keys**: `boolean`

#### lastIndexOf?

> `optional` **lastIndexOf**: `boolean`

#### length?

> `optional` **length**: `boolean`

Gets or sets the length of the array. This is a number one higher than the highest index in the array.

#### map?

> `optional` **map**: `boolean`

#### pop?

> `optional` **pop**: `boolean`

#### push?

> `optional` **push**: `boolean`

#### reduce?

> `optional` **reduce**: `boolean`

#### reduceRight?

> `optional` **reduceRight**: `boolean`

#### reverse?

> `optional` **reverse**: `boolean`

#### shift?

> `optional` **shift**: `boolean`

#### slice?

> `optional` **slice**: `boolean`

#### some?

> `optional` **some**: `boolean`

#### sort?

> `optional` **sort**: `boolean`

#### splice?

> `optional` **splice**: `boolean`

#### toLocaleString?

> `optional` **toLocaleString**: `boolean`

#### toReversed?

> `optional` **toReversed**: `boolean`

#### toSorted?

> `optional` **toSorted**: `boolean`

#### toSpliced?

> `optional` **toSpliced**: `boolean`

#### toString?

> `optional` **toString**: `boolean`

#### unshift?

> `optional` **unshift**: `boolean`

#### values?

> `optional` **values**: `boolean`

#### with?

> `optional` **with**: `boolean`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`[unscopables]`](../../../core/PkiBase/classes/PkiSet.md#unscopables)

---

### length

> **length**: `number`

Gets or sets the length of the array. This is a number one higher than the highest index in the array.

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`length`](../../../core/PkiBase/classes/PkiSet.md#length)

---

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`maxSize`](../../../core/PkiBase/classes/PkiSet.md#maxsize)

---

### \[species\]

> `readonly` `static` **\[species\]**: `ArrayConstructor`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`[species]`](../../../core/PkiBase/classes/PkiSet.md#species)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`pemHeader`](../../../core/PkiBase/classes/PkiSet.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`pkiType`](../../../core/PkiBase/classes/PkiSet.md#pkitype)

## Methods

### \[iterator\]()

> **\[iterator\]**(): `ArrayIterator`\<[`Attribute`](../../Attribute/classes/Attribute.md)\>

Iterator

#### Returns

`ArrayIterator`\<[`Attribute`](../../Attribute/classes/Attribute.md)\>

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`[iterator]`](../../../core/PkiBase/classes/PkiSet.md#iterator)

---

### at()

> **at**(`index`): `undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

Returns the item located at the specified index.

#### Parameters

##### index

`number`

The zero-based index of the desired code unit. A negative index will count back from the last item.

#### Returns

`undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`at`](../../../core/PkiBase/classes/PkiSet.md#at)

---

### concat()

#### Call Signature

> **concat**(...`items`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Combines two or more arrays.
This method returns a new array without modifying any existing arrays.

##### Parameters

###### items

...`ConcatArray`\<[`Attribute`](../../Attribute/classes/Attribute.md)\>[]

Additional arrays and/or items to add to the end of the array.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`concat`](../../../core/PkiBase/classes/PkiSet.md#concat)

#### Call Signature

> **concat**(...`items`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Combines two or more arrays.
This method returns a new array without modifying any existing arrays.

##### Parameters

###### items

...([`Attribute`](../../Attribute/classes/Attribute.md) \| `ConcatArray`\<[`Attribute`](../../Attribute/classes/Attribute.md)\>)[]

Additional arrays and/or items to add to the end of the array.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`concat`](../../../core/PkiBase/classes/PkiSet.md#concat)

---

### copyWithin()

> **copyWithin**(`target`, `start`, `end?`): `this`

Returns the this object after copying a section of the array identified by start and end
to the same array starting at position target

#### Parameters

##### target

`number`

If target is negative, it is treated as length+target where length is the
length of the array.

##### start

`number`

If start is negative, it is treated as length+start. If end is negative, it
is treated as length+end.

##### end?

`number`

If not specified, length of the this object is used as its default value.

#### Returns

`this`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`copyWithin`](../../../core/PkiBase/classes/PkiSet.md#copywithin)

---

### entries()

> **entries**(): `ArrayIterator`\<\[`number`, [`Attribute`](../../Attribute/classes/Attribute.md)\]\>

Returns an iterable of key, value pairs for every entry in the array

#### Returns

`ArrayIterator`\<\[`number`, [`Attribute`](../../Attribute/classes/Attribute.md)\]\>

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`entries`](../../../core/PkiBase/classes/PkiSet.md#entries)

---

### equals()

> **equals**(`other`): `boolean`

Compares this set with another for equality.
Two sets are considered equal if they have the same length and
all corresponding items are equal.

#### Parameters

##### other

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md)\<[`Attribute`](../../Attribute/classes/Attribute.md)\>

The other set to compare with

#### Returns

`boolean`

true if the sets are equal, false otherwise

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`equals`](../../../core/PkiBase/classes/PkiSet.md#equals)

---

### every()

#### Call Signature

> **every**\<`S`\>(`predicate`, `thisArg?`): `this is S[]`

Determines whether all the members of an array satisfy the specified test.

##### Type Parameters

###### S

`S` _extends_ [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### predicate

(`value`, `index`, `array`) => `value is S`

A function that accepts up to three arguments. The every method calls
the predicate function for each element in the array until the predicate returns a value
which is coercible to the Boolean value false, or until the end of the array.

###### thisArg?

`any`

An object to which the this keyword can refer in the predicate function.
If thisArg is omitted, undefined is used as the this value.

##### Returns

`this is S[]`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`every`](../../../core/PkiBase/classes/PkiSet.md#every)

#### Call Signature

> **every**(`predicate`, `thisArg?`): `boolean`

Determines whether all the members of an array satisfy the specified test.

##### Parameters

###### predicate

(`value`, `index`, `array`) => `unknown`

A function that accepts up to three arguments. The every method calls
the predicate function for each element in the array until the predicate returns a value
which is coercible to the Boolean value false, or until the end of the array.

###### thisArg?

`any`

An object to which the this keyword can refer in the predicate function.
If thisArg is omitted, undefined is used as the this value.

##### Returns

`boolean`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`every`](../../../core/PkiBase/classes/PkiSet.md#every)

---

### fill()

> **fill**(`value`, `start?`, `end?`): `this`

Changes all array elements from `start` to `end` index to a static `value` and returns the modified array

#### Parameters

##### value

[`Attribute`](../../Attribute/classes/Attribute.md)

value to fill array section with

##### start?

`number`

index to start filling the array at. If start is negative, it is treated as
length+start where length is the length of the array.

##### end?

`number`

index to stop filling the array at. If end is negative, it is treated as
length+end.

#### Returns

`this`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`fill`](../../../core/PkiBase/classes/PkiSet.md#fill)

---

### filter()

#### Call Signature

> **filter**\<`S`\>(`predicate`, `thisArg?`): `S`[]

Returns the elements of an array that meet the condition specified in a callback function.

##### Type Parameters

###### S

`S` _extends_ [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### predicate

(`value`, `index`, `array`) => `value is S`

A function that accepts up to three arguments. The filter method calls the predicate function one time for each element in the array.

###### thisArg?

`any`

An object to which the this keyword can refer in the predicate function. If thisArg is omitted, undefined is used as the this value.

##### Returns

`S`[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`filter`](../../../core/PkiBase/classes/PkiSet.md#filter)

#### Call Signature

> **filter**(`predicate`, `thisArg?`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Returns the elements of an array that meet the condition specified in a callback function.

##### Parameters

###### predicate

(`value`, `index`, `array`) => `unknown`

A function that accepts up to three arguments. The filter method calls the predicate function one time for each element in the array.

###### thisArg?

`any`

An object to which the this keyword can refer in the predicate function. If thisArg is omitted, undefined is used as the this value.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`filter`](../../../core/PkiBase/classes/PkiSet.md#filter)

---

### find()

#### Call Signature

> **find**\<`S`\>(`predicate`, `thisArg?`): `undefined` \| `S`

Returns the value of the first element in the array where predicate is true, and undefined
otherwise.

##### Type Parameters

###### S

`S` _extends_ [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### predicate

(`value`, `index`, `obj`) => `value is S`

find calls predicate once for each element of the array, in ascending
order, until it finds one where predicate returns true. If such an element is found, find
immediately returns that element value. Otherwise, find returns undefined.

###### thisArg?

`any`

If provided, it will be used as the this value for each invocation of
predicate. If it is not provided, undefined is used instead.

##### Returns

`undefined` \| `S`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`find`](../../../core/PkiBase/classes/PkiSet.md#find)

#### Call Signature

> **find**(`predicate`, `thisArg?`): `undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### predicate

(`value`, `index`, `obj`) => `unknown`

###### thisArg?

`any`

##### Returns

`undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`find`](../../../core/PkiBase/classes/PkiSet.md#find)

---

### findIndex()

> **findIndex**(`predicate`, `thisArg?`): `number`

Returns the index of the first element in the array where predicate is true, and -1
otherwise.

#### Parameters

##### predicate

(`value`, `index`, `obj`) => `unknown`

find calls predicate once for each element of the array, in ascending
order, until it finds one where predicate returns true. If such an element is found,
findIndex immediately returns that element index. Otherwise, findIndex returns -1.

##### thisArg?

`any`

If provided, it will be used as the this value for each invocation of
predicate. If it is not provided, undefined is used instead.

#### Returns

`number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`findIndex`](../../../core/PkiBase/classes/PkiSet.md#findindex)

---

### findLast()

#### Call Signature

> **findLast**\<`S`\>(`predicate`, `thisArg?`): `undefined` \| `S`

Returns the value of the last element in the array where predicate is true, and undefined
otherwise.

##### Type Parameters

###### S

`S` _extends_ [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### predicate

(`value`, `index`, `array`) => `value is S`

findLast calls predicate once for each element of the array, in descending
order, until it finds one where predicate returns true. If such an element is found, findLast
immediately returns that element value. Otherwise, findLast returns undefined.

###### thisArg?

`any`

If provided, it will be used as the this value for each invocation of
predicate. If it is not provided, undefined is used instead.

##### Returns

`undefined` \| `S`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`findLast`](../../../core/PkiBase/classes/PkiSet.md#findlast)

#### Call Signature

> **findLast**(`predicate`, `thisArg?`): `undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### predicate

(`value`, `index`, `array`) => `unknown`

###### thisArg?

`any`

##### Returns

`undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`findLast`](../../../core/PkiBase/classes/PkiSet.md#findlast)

---

### findLastIndex()

> **findLastIndex**(`predicate`, `thisArg?`): `number`

Returns the index of the last element in the array where predicate is true, and -1
otherwise.

#### Parameters

##### predicate

(`value`, `index`, `array`) => `unknown`

findLastIndex calls predicate once for each element of the array, in descending
order, until it finds one where predicate returns true. If such an element is found,
findLastIndex immediately returns that element index. Otherwise, findLastIndex returns -1.

##### thisArg?

`any`

If provided, it will be used as the this value for each invocation of
predicate. If it is not provided, undefined is used instead.

#### Returns

`number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`findLastIndex`](../../../core/PkiBase/classes/PkiSet.md#findlastindex)

---

### flat()

> **flat**\<`A`, `D`\>(`this`, `depth?`): `FlatArray`\<`A`, `D`\>[]

Returns a new array with all sub-array elements concatenated into it recursively up to the
specified depth.

#### Type Parameters

##### A

`A`

##### D

`D` _extends_ `number` = `1`

#### Parameters

##### this

`A`

##### depth?

`D`

The maximum recursion depth

#### Returns

`FlatArray`\<`A`, `D`\>[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`flat`](../../../core/PkiBase/classes/PkiSet.md#flat)

---

### flatMap()

> **flatMap**\<`U`, `This`\>(`callback`, `thisArg?`): `U`[]

Calls a defined callback function on each element of an array. Then, flattens the result into
a new array.
This is identical to a map followed by flat with depth 1.

#### Type Parameters

##### U

`U`

##### This

`This` = `undefined`

#### Parameters

##### callback

(`this`, `value`, `index`, `array`) => `U` \| readonly `U`[]

A function that accepts up to three arguments. The flatMap method calls the
callback function one time for each element in the array.

##### thisArg?

`This`

An object to which the this keyword can refer in the callback function. If
thisArg is omitted, undefined is used as the this value.

#### Returns

`U`[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`flatMap`](../../../core/PkiBase/classes/PkiSet.md#flatmap)

---

### forEach()

> **forEach**(`callbackfn`, `thisArg?`): `void`

Performs the specified action for each element in an array.

#### Parameters

##### callbackfn

(`value`, `index`, `array`) => `void`

A function that accepts up to three arguments. forEach calls the callbackfn function one time for each element in the array.

##### thisArg?

`any`

An object to which the this keyword can refer in the callbackfn function. If thisArg is omitted, undefined is used as the this value.

#### Returns

`void`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`forEach`](../../../core/PkiBase/classes/PkiSet.md#foreach)

---

### includes()

> **includes**(`searchElement`, `fromIndex?`): `boolean`

Determines whether an array includes a certain element, returning true or false as appropriate.

#### Parameters

##### searchElement

[`Attribute`](../../Attribute/classes/Attribute.md)

The element to search for.

##### fromIndex?

`number`

The position in this array at which to begin searching for searchElement.

#### Returns

`boolean`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`includes`](../../../core/PkiBase/classes/PkiSet.md#includes)

---

### indexOf()

> **indexOf**(`searchElement`, `fromIndex?`): `number`

Returns the index of the first occurrence of a value in an array, or -1 if it is not present.

#### Parameters

##### searchElement

[`Attribute`](../../Attribute/classes/Attribute.md)

The value to locate in the array.

##### fromIndex?

`number`

The array index at which to begin the search. If fromIndex is omitted, the search starts at index 0.

#### Returns

`number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`indexOf`](../../../core/PkiBase/classes/PkiSet.md#indexof)

---

### join()

> **join**(`separator?`): `string`

Adds all the elements of an array into a string, separated by the specified separator string.

#### Parameters

##### separator?

`string`

A string used to separate one element of the array from the next in the resulting string. If omitted, the array elements are separated with a comma.

#### Returns

`string`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`join`](../../../core/PkiBase/classes/PkiSet.md#join)

---

### keys()

> **keys**(): `ArrayIterator`\<`number`\>

Returns an iterable of keys in the array

#### Returns

`ArrayIterator`\<`number`\>

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`keys`](../../../core/PkiBase/classes/PkiSet.md#keys)

---

### lastIndexOf()

> **lastIndexOf**(`searchElement`, `fromIndex?`): `number`

Returns the index of the last occurrence of a specified value in an array, or -1 if it is not present.

#### Parameters

##### searchElement

[`Attribute`](../../Attribute/classes/Attribute.md)

The value to locate in the array.

##### fromIndex?

`number`

The array index at which to begin searching backward. If fromIndex is omitted, the search starts at the last index in the array.

#### Returns

`number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`lastIndexOf`](../../../core/PkiBase/classes/PkiSet.md#lastindexof)

---

### map()

> **map**\<`U`\>(`callbackfn`, `thisArg?`): `U`[]

Calls a defined callback function on each element of an array, and returns an array that contains the results.

#### Type Parameters

##### U

`U`

#### Parameters

##### callbackfn

(`value`, `index`, `array`) => `U`

A function that accepts up to three arguments. The map method calls the callbackfn function one time for each element in the array.

##### thisArg?

`any`

An object to which the this keyword can refer in the callbackfn function. If thisArg is omitted, undefined is used as the this value.

#### Returns

`U`[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`map`](../../../core/PkiBase/classes/PkiSet.md#map)

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this set as a different PKI type.

#### Type Parameters

##### T

`T`

The target type to parse as

#### Parameters

##### type

[`ParseableAsn1`](../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`parseAs`](../../../core/PkiBase/classes/PkiSet.md#parseas)

---

### pop()

> **pop**(): `undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

Removes the last element from an array and returns it.
If the array is empty, undefined is returned and the array is not modified.

#### Returns

`undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`pop`](../../../core/PkiBase/classes/PkiSet.md#pop)

---

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...[`Attribute`](../../Attribute/classes/Attribute.md)[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`push`](../../../core/PkiBase/classes/PkiSet.md#push)

---

### reduce()

#### Call Signature

> **reduce**(`callbackfn`): [`Attribute`](../../Attribute/classes/Attribute.md)

Calls the specified callback function for all the elements in an array. The return value of the callback function is the accumulated result, and is provided as an argument in the next call to the callback function.

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`Attribute`](../../Attribute/classes/Attribute.md)

A function that accepts up to four arguments. The reduce method calls the callbackfn function one time for each element in the array.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reduce`](../../../core/PkiBase/classes/PkiSet.md#reduce)

#### Call Signature

> **reduce**(`callbackfn`, `initialValue`): [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`Attribute`](../../Attribute/classes/Attribute.md)

###### initialValue

[`Attribute`](../../Attribute/classes/Attribute.md)

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reduce`](../../../core/PkiBase/classes/PkiSet.md#reduce)

#### Call Signature

> **reduce**\<`U`\>(`callbackfn`, `initialValue`): `U`

Calls the specified callback function for all the elements in an array. The return value of the callback function is the accumulated result, and is provided as an argument in the next call to the callback function.

##### Type Parameters

###### U

`U`

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => `U`

A function that accepts up to four arguments. The reduce method calls the callbackfn function one time for each element in the array.

###### initialValue

`U`

If initialValue is specified, it is used as the initial value to start the accumulation. The first call to the callbackfn function provides this value as an argument instead of an array value.

##### Returns

`U`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reduce`](../../../core/PkiBase/classes/PkiSet.md#reduce)

---

### reduceRight()

#### Call Signature

> **reduceRight**(`callbackfn`): [`Attribute`](../../Attribute/classes/Attribute.md)

Calls the specified callback function for all the elements in an array, in descending order. The return value of the callback function is the accumulated result, and is provided as an argument in the next call to the callback function.

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`Attribute`](../../Attribute/classes/Attribute.md)

A function that accepts up to four arguments. The reduceRight method calls the callbackfn function one time for each element in the array.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reduceRight`](../../../core/PkiBase/classes/PkiSet.md#reduceright)

#### Call Signature

> **reduceRight**(`callbackfn`, `initialValue`): [`Attribute`](../../Attribute/classes/Attribute.md)

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`Attribute`](../../Attribute/classes/Attribute.md)

###### initialValue

[`Attribute`](../../Attribute/classes/Attribute.md)

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reduceRight`](../../../core/PkiBase/classes/PkiSet.md#reduceright)

#### Call Signature

> **reduceRight**\<`U`\>(`callbackfn`, `initialValue`): `U`

Calls the specified callback function for all the elements in an array, in descending order. The return value of the callback function is the accumulated result, and is provided as an argument in the next call to the callback function.

##### Type Parameters

###### U

`U`

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => `U`

A function that accepts up to four arguments. The reduceRight method calls the callbackfn function one time for each element in the array.

###### initialValue

`U`

If initialValue is specified, it is used as the initial value to start the accumulation. The first call to the callbackfn function provides this value as an argument instead of an array value.

##### Returns

`U`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reduceRight`](../../../core/PkiBase/classes/PkiSet.md#reduceright)

---

### reverse()

> **reverse**(): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Reverses the elements in an array in place.
This method mutates the array and returns a reference to the same array.

#### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`reverse`](../../../core/PkiBase/classes/PkiSet.md#reverse)

---

### shift()

> **shift**(): `undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

Removes the first element from an array and returns it.
If the array is empty, undefined is returned and the array is not modified.

#### Returns

`undefined` \| [`Attribute`](../../Attribute/classes/Attribute.md)

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`shift`](../../../core/PkiBase/classes/PkiSet.md#shift)

---

### slice()

> **slice**(`start?`, `end?`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Returns a copy of a section of an array.
For both start and end, a negative index can be used to indicate an offset from the end of the array.
For example, -2 refers to the second to last element of the array.

#### Parameters

##### start?

`number`

The beginning index of the specified portion of the array.
If start is undefined, then the slice begins at index 0.

##### end?

`number`

The end index of the specified portion of the array. This is exclusive of the element at the index 'end'.
If end is undefined, then the slice extends to the end of the array.

#### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`slice`](../../../core/PkiBase/classes/PkiSet.md#slice)

---

### some()

> **some**(`predicate`, `thisArg?`): `boolean`

Determines whether the specified callback function returns true for any element of an array.

#### Parameters

##### predicate

(`value`, `index`, `array`) => `unknown`

A function that accepts up to three arguments. The some method calls
the predicate function for each element in the array until the predicate returns a value
which is coercible to the Boolean value true, or until the end of the array.

##### thisArg?

`any`

An object to which the this keyword can refer in the predicate function.
If thisArg is omitted, undefined is used as the this value.

#### Returns

`boolean`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`some`](../../../core/PkiBase/classes/PkiSet.md#some)

---

### sort()

> **sort**(`compareFn?`): `this`

Sorts an array in place.
This method mutates the array and returns a reference to the same array.

#### Parameters

##### compareFn?

(`a`, `b`) => `number`

Function used to determine the order of the elements. It is expected to return
a negative value if the first argument is less than the second argument, zero if they're equal, and a positive
value otherwise. If omitted, the elements are sorted in ascending, UTF-16 code unit order.

```ts
;[11, 2, 22, 1].sort((a, b) => a - b)
```

#### Returns

`this`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`sort`](../../../core/PkiBase/classes/PkiSet.md#sort)

---

### splice()

#### Call Signature

> **splice**(`start`, `deleteCount?`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Removes elements from an array and, if necessary, inserts new elements in their place, returning the deleted elements.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount?

`number`

The number of elements to remove.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

An array containing the elements that were deleted.

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`splice`](../../../core/PkiBase/classes/PkiSet.md#splice)

#### Call Signature

> **splice**(`start`, `deleteCount`, ...`items`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Removes elements from an array and, if necessary, inserts new elements in their place, returning the deleted elements.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount

`number`

The number of elements to remove.

###### items

...[`Attribute`](../../Attribute/classes/Attribute.md)[]

Elements to insert into the array in place of the deleted elements.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

An array containing the elements that were deleted.

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`splice`](../../../core/PkiBase/classes/PkiSet.md#splice)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this set to ASN.1 SET structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

An ASN.1 SET containing all items in this collection

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toAsn1`](../../../core/PkiBase/classes/PkiSet.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this set to DER format.

#### Returns

`Uint8Array`

The DER-encoded bytes of this set

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toDer`](../../../core/PkiBase/classes/PkiSet.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this set.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toHumanString`](../../../core/PkiBase/classes/PkiSet.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toJSON`](../../../core/PkiBase/classes/PkiSet.md#tojson)

---

### toLocaleString()

#### Call Signature

> **toLocaleString**(): `string`

Returns a string representation of an array. The elements are converted to string using their toLocaleString methods.

##### Returns

`string`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toLocaleString`](../../../core/PkiBase/classes/PkiSet.md#tolocalestring)

#### Call Signature

> **toLocaleString**(`locales`, `options?`): `string`

##### Parameters

###### locales

`string` | `string`[]

###### options?

`NumberFormatOptions` & `DateTimeFormatOptions`

##### Returns

`string`

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toLocaleString`](../../../core/PkiBase/classes/PkiSet.md#tolocalestring)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toPem`](../../../core/PkiBase/classes/PkiSet.md#topem)

---

### toReversed()

> **toReversed**(): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Returns a copy of an array with its elements reversed.

#### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toReversed`](../../../core/PkiBase/classes/PkiSet.md#toreversed)

---

### toSorted()

> **toSorted**(`compareFn?`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Returns a copy of an array with its elements sorted.

#### Parameters

##### compareFn?

(`a`, `b`) => `number`

Function used to determine the order of the elements. It is expected to return
a negative value if the first argument is less than the second argument, zero if they're equal, and a positive
value otherwise. If omitted, the elements are sorted in ascending, UTF-16 code unit order.

```ts
;[11, 2, 22, 1].toSorted((a, b) => a - b) // [1, 2, 11, 22]
```

#### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toSorted`](../../../core/PkiBase/classes/PkiSet.md#tosorted)

---

### toSpliced()

#### Call Signature

> **toSpliced**(`start`, `deleteCount`, ...`items`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Copies an array and removes elements and, if necessary, inserts new elements in their place. Returns the copied array.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount

`number`

The number of elements to remove.

###### items

...[`Attribute`](../../Attribute/classes/Attribute.md)[]

Elements to insert into the copied array in place of the deleted elements.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

The copied array.

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toSpliced`](../../../core/PkiBase/classes/PkiSet.md#tospliced)

#### Call Signature

> **toSpliced**(`start`, `deleteCount?`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Copies an array and removes elements while returning the remaining elements.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount?

`number`

The number of elements to remove.

##### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

A copy of the original array with the remaining elements.

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toSpliced`](../../../core/PkiBase/classes/PkiSet.md#tospliced)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toString`](../../../core/PkiBase/classes/PkiSet.md#tostring)

---

### unshift()

> **unshift**(...`items`): `number`

Inserts new elements at the start of an array, and returns the new length of the array.

#### Parameters

##### items

...[`Attribute`](../../Attribute/classes/Attribute.md)[]

Elements to insert at the start of the array.

#### Returns

`number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`unshift`](../../../core/PkiBase/classes/PkiSet.md#unshift)

---

### values()

> **values**(): `ArrayIterator`\<[`Attribute`](../../Attribute/classes/Attribute.md)\>

Returns an iterable of values in the array

#### Returns

`ArrayIterator`\<[`Attribute`](../../Attribute/classes/Attribute.md)\>

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`values`](../../../core/PkiBase/classes/PkiSet.md#values)

---

### with()

> **with**(`index`, `value`): [`Attribute`](../../Attribute/classes/Attribute.md)[]

Copies an array, then overwrites the value at the provided index with the
given value. If the index is negative, then it replaces from the end
of the array.

#### Parameters

##### index

`number`

The index of the value to overwrite. If the index is
negative, then it replaces from the end of the array.

##### value

[`Attribute`](../../Attribute/classes/Attribute.md)

The value to write into the copied array.

#### Returns

[`Attribute`](../../Attribute/classes/Attribute.md)[]

The copied array with the updated value.

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`with`](../../../core/PkiBase/classes/PkiSet.md#with)

---

### from()

#### Call Signature

> `static` **from**\<`T`\>(`arrayLike`): `T`[]

Creates an array from an array-like object.

##### Type Parameters

###### T

`T`

##### Parameters

###### arrayLike

`ArrayLike`\<`T`\>

An array-like object to convert to an array.

##### Returns

`T`[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`from`](../../../core/PkiBase/classes/PkiSet.md#from)

#### Call Signature

> `static` **from**\<`T`, `U`\>(`arrayLike`, `mapfn`, `thisArg?`): `U`[]

Creates an array from an iterable object.

##### Type Parameters

###### T

`T`

###### U

`U`

##### Parameters

###### arrayLike

`ArrayLike`\<`T`\>

An array-like object to convert to an array.

###### mapfn

(`v`, `k`) => `U`

A mapping function to call on every element of the array.

###### thisArg?

`any`

Value of 'this' used to invoke the mapfn.

##### Returns

`U`[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`from`](../../../core/PkiBase/classes/PkiSet.md#from)

#### Call Signature

> `static` **from**\<`T`\>(`iterable`): `T`[]

Creates an array from an iterable object.

##### Type Parameters

###### T

`T`

##### Parameters

###### iterable

An iterable object to convert to an array.

`Iterable`\<`T`, `any`, `any`\> | `ArrayLike`\<`T`\>

##### Returns

`T`[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`from`](../../../core/PkiBase/classes/PkiSet.md#from)

#### Call Signature

> `static` **from**\<`T`, `U`\>(`iterable`, `mapfn`, `thisArg?`): `U`[]

Creates an array from an iterable object.

##### Type Parameters

###### T

`T`

###### U

`U`

##### Parameters

###### iterable

An iterable object to convert to an array.

`Iterable`\<`T`, `any`, `any`\> | `ArrayLike`\<`T`\>

###### mapfn

(`v`, `k`) => `U`

A mapping function to call on every element of the array.

###### thisArg?

`any`

Value of 'this' used to invoke the mapfn.

##### Returns

`U`[]

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`from`](../../../core/PkiBase/classes/PkiSet.md#from)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `Attributes`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`Attributes`

---

### fromAsync()

#### Call Signature

> `static` **fromAsync**\<`T`\>(`iterableOrArrayLike`): `Promise`\<`T`[]\>

Creates an array from an async iterator or iterable object.

##### Type Parameters

###### T

`T`

##### Parameters

###### iterableOrArrayLike

An async iterator or array-like object to convert to an array.

`AsyncIterable`\<`T`, `any`, `any`\> | `Iterable`\<`T` \| `PromiseLike`\<`T`\>, `any`, `any`\> | `ArrayLike`\<`T` \| `PromiseLike`\<`T`\>\>

##### Returns

`Promise`\<`T`[]\>

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`fromAsync`](../../../core/PkiBase/classes/PkiSet.md#fromasync)

#### Call Signature

> `static` **fromAsync**\<`T`, `U`\>(`iterableOrArrayLike`, `mapFn`, `thisArg?`): `Promise`\<`Awaited`\<`U`\>[]\>

Creates an array from an async iterator or iterable object.

##### Type Parameters

###### T

`T`

###### U

`U`

##### Parameters

###### iterableOrArrayLike

An async iterator or array-like object to convert to an array.

`AsyncIterable`\<`T`, `any`, `any`\> | `Iterable`\<`T`, `any`, `any`\> | `ArrayLike`\<`T`\>

###### mapFn

(`value`, `index`) => `U`

###### thisArg?

`any`

Value of 'this' used when executing mapfn.

##### Returns

`Promise`\<`Awaited`\<`U`\>[]\>

##### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`fromAsync`](../../../core/PkiBase/classes/PkiSet.md#fromasync)

---

### isArray()

> `static` **isArray**(`arg`): `arg is any[]`

#### Parameters

##### arg

`any`

#### Returns

`arg is any[]`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`isArray`](../../../core/PkiBase/classes/PkiSet.md#isarray)

---

### of()

> `static` **of**\<`T`\>(...`items`): `T`[]

Returns a new array from a set of elements.

#### Type Parameters

##### T

`T`

#### Parameters

##### items

...`T`[]

A set of elements to include in the new array object.

#### Returns

`T`[]

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`of`](../../../core/PkiBase/classes/PkiSet.md#of)
