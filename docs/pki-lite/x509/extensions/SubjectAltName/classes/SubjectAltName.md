[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [x509/extensions/SubjectAltName](../README.md) / SubjectAltName

# Class: SubjectAltName

Represents a SEQUENCE OF PKI objects in ASN.1.

A SEQUENCE contains an ordered collection of objects, which may be of
different types. This class provides SEQUENCE-specific ASN.1 encoding
and comparison methods.

## Extends

- [`GeneralNames`](../../../GeneralName/classes/GeneralNames.md)

## Indexable

\[`n`: `number`\]: [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

## Constructors

### Constructor

> **new SubjectAltName**(`arrayLength`): `SubjectAltName`

#### Parameters

##### arrayLength

`number`

#### Returns

`SubjectAltName`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`constructor`](../../../GeneralName/classes/GeneralNames.md#constructor)

### Constructor

> **new SubjectAltName**(...`items`): `SubjectAltName`

#### Parameters

##### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

#### Returns

`SubjectAltName`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`constructor`](../../../GeneralName/classes/GeneralNames.md#constructor)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`[unscopables]`](../../../GeneralName/classes/GeneralNames.md#unscopables)

---

### length

> **length**: `number`

Gets or sets the length of the array. This is a number one higher than the highest index in the array.

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`length`](../../../GeneralName/classes/GeneralNames.md#length)

---

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`maxSize`](../../../GeneralName/classes/GeneralNames.md#maxsize)

---

### \[species\]

> `readonly` `static` **\[species\]**: `ArrayConstructor`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`[species]`](../../../GeneralName/classes/GeneralNames.md#species)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`pemHeader`](../../../GeneralName/classes/GeneralNames.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`pkiType`](../../../GeneralName/classes/GeneralNames.md#pkitype)

## Methods

### \[iterator\]()

> **\[iterator\]**(): `ArrayIterator`\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

Iterator

#### Returns

`ArrayIterator`\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`[iterator]`](../../../GeneralName/classes/GeneralNames.md#iterator)

---

### at()

> **at**(`index`): `undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

Returns the item located at the specified index.

#### Parameters

##### index

`number`

The zero-based index of the desired code unit. A negative index will count back from the last item.

#### Returns

`undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`at`](../../../GeneralName/classes/GeneralNames.md#at)

---

### concat()

#### Call Signature

> **concat**(...`items`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Combines two or more arrays.
This method returns a new array without modifying any existing arrays.

##### Parameters

###### items

...`ConcatArray`\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>[]

Additional arrays and/or items to add to the end of the array.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`concat`](../../../GeneralName/classes/GeneralNames.md#concat)

#### Call Signature

> **concat**(...`items`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Combines two or more arrays.
This method returns a new array without modifying any existing arrays.

##### Parameters

###### items

...([`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md) \| `ConcatArray`\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>)[]

Additional arrays and/or items to add to the end of the array.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`concat`](../../../GeneralName/classes/GeneralNames.md#concat)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`copyWithin`](../../../GeneralName/classes/GeneralNames.md#copywithin)

---

### entries()

> **entries**(): `ArrayIterator`\<\[`number`, [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\]\>

Returns an iterable of key, value pairs for every entry in the array

#### Returns

`ArrayIterator`\<\[`number`, [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\]\>

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`entries`](../../../GeneralName/classes/GeneralNames.md#entries)

---

### equals()

> **equals**(`other`): `boolean`

Compares this sequence with another for equality.
Two sequences are considered equal if they have the same length and
all corresponding items are equal in the same order.

#### Parameters

##### other

[`PkiSequence`](../../../../core/PkiBase/classes/PkiSequence.md)\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

The other sequence to compare with

#### Returns

`boolean`

true if the sequences are equal, false otherwise

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`equals`](../../../GeneralName/classes/GeneralNames.md#equals)

---

### every()

#### Call Signature

> **every**\<`S`\>(`predicate`, `thisArg?`): `this is S[]`

Determines whether all the members of an array satisfy the specified test.

##### Type Parameters

###### S

`S` _extends_ [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`every`](../../../GeneralName/classes/GeneralNames.md#every)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`every`](../../../GeneralName/classes/GeneralNames.md#every)

---

### fill()

> **fill**(`value`, `start?`, `end?`): `this`

Changes all array elements from `start` to `end` index to a static `value` and returns the modified array

#### Parameters

##### value

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`fill`](../../../GeneralName/classes/GeneralNames.md#fill)

---

### filter()

#### Call Signature

> **filter**\<`S`\>(`predicate`, `thisArg?`): `S`[]

Returns the elements of an array that meet the condition specified in a callback function.

##### Type Parameters

###### S

`S` _extends_ [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`filter`](../../../GeneralName/classes/GeneralNames.md#filter)

#### Call Signature

> **filter**(`predicate`, `thisArg?`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Returns the elements of an array that meet the condition specified in a callback function.

##### Parameters

###### predicate

(`value`, `index`, `array`) => `unknown`

A function that accepts up to three arguments. The filter method calls the predicate function one time for each element in the array.

###### thisArg?

`any`

An object to which the this keyword can refer in the predicate function. If thisArg is omitted, undefined is used as the this value.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`filter`](../../../GeneralName/classes/GeneralNames.md#filter)

---

### find()

#### Call Signature

> **find**\<`S`\>(`predicate`, `thisArg?`): `undefined` \| `S`

Returns the value of the first element in the array where predicate is true, and undefined
otherwise.

##### Type Parameters

###### S

`S` _extends_ [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`find`](../../../GeneralName/classes/GeneralNames.md#find)

#### Call Signature

> **find**(`predicate`, `thisArg?`): `undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Parameters

###### predicate

(`value`, `index`, `obj`) => `unknown`

###### thisArg?

`any`

##### Returns

`undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`find`](../../../GeneralName/classes/GeneralNames.md#find)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`findIndex`](../../../GeneralName/classes/GeneralNames.md#findindex)

---

### findLast()

#### Call Signature

> **findLast**\<`S`\>(`predicate`, `thisArg?`): `undefined` \| `S`

Returns the value of the last element in the array where predicate is true, and undefined
otherwise.

##### Type Parameters

###### S

`S` _extends_ [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`findLast`](../../../GeneralName/classes/GeneralNames.md#findlast)

#### Call Signature

> **findLast**(`predicate`, `thisArg?`): `undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Parameters

###### predicate

(`value`, `index`, `array`) => `unknown`

###### thisArg?

`any`

##### Returns

`undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`findLast`](../../../GeneralName/classes/GeneralNames.md#findlast)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`findLastIndex`](../../../GeneralName/classes/GeneralNames.md#findlastindex)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`flat`](../../../GeneralName/classes/GeneralNames.md#flat)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`flatMap`](../../../GeneralName/classes/GeneralNames.md#flatmap)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`forEach`](../../../GeneralName/classes/GeneralNames.md#foreach)

---

### includes()

> **includes**(`searchElement`, `fromIndex?`): `boolean`

Determines whether an array includes a certain element, returning true or false as appropriate.

#### Parameters

##### searchElement

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

The element to search for.

##### fromIndex?

`number`

The position in this array at which to begin searching for searchElement.

#### Returns

`boolean`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`includes`](../../../GeneralName/classes/GeneralNames.md#includes)

---

### indexOf()

> **indexOf**(`searchElement`, `fromIndex?`): `number`

Returns the index of the first occurrence of a value in an array, or -1 if it is not present.

#### Parameters

##### searchElement

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

The value to locate in the array.

##### fromIndex?

`number`

The array index at which to begin the search. If fromIndex is omitted, the search starts at index 0.

#### Returns

`number`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`indexOf`](../../../GeneralName/classes/GeneralNames.md#indexof)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`join`](../../../GeneralName/classes/GeneralNames.md#join)

---

### keys()

> **keys**(): `ArrayIterator`\<`number`\>

Returns an iterable of keys in the array

#### Returns

`ArrayIterator`\<`number`\>

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`keys`](../../../GeneralName/classes/GeneralNames.md#keys)

---

### lastIndexOf()

> **lastIndexOf**(`searchElement`, `fromIndex?`): `number`

Returns the index of the last occurrence of a specified value in an array, or -1 if it is not present.

#### Parameters

##### searchElement

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

The value to locate in the array.

##### fromIndex?

`number`

The array index at which to begin searching backward. If fromIndex is omitted, the search starts at the last index in the array.

#### Returns

`number`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`lastIndexOf`](../../../GeneralName/classes/GeneralNames.md#lastindexof)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`map`](../../../GeneralName/classes/GeneralNames.md#map)

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this sequence as a different PKI type.

#### Type Parameters

##### T

`T`

The target type to parse as

#### Parameters

##### type

[`ParseableAsn1`](../../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`parseAs`](../../../GeneralName/classes/GeneralNames.md#parseas)

---

### pop()

> **pop**(): `undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

Removes the last element from an array and returns it.
If the array is empty, undefined is returned and the array is not modified.

#### Returns

`undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`pop`](../../../GeneralName/classes/GeneralNames.md#pop)

---

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`push`](../../../GeneralName/classes/GeneralNames.md#push)

---

### reduce()

#### Call Signature

> **reduce**(`callbackfn`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

Calls the specified callback function for all the elements in an array. The return value of the callback function is the accumulated result, and is provided as an argument in the next call to the callback function.

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

A function that accepts up to four arguments. The reduce method calls the callbackfn function one time for each element in the array.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reduce`](../../../GeneralName/classes/GeneralNames.md#reduce)

#### Call Signature

> **reduce**(`callbackfn`, `initialValue`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

###### initialValue

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reduce`](../../../GeneralName/classes/GeneralNames.md#reduce)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reduce`](../../../GeneralName/classes/GeneralNames.md#reduce)

---

### reduceRight()

#### Call Signature

> **reduceRight**(`callbackfn`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

Calls the specified callback function for all the elements in an array, in descending order. The return value of the callback function is the accumulated result, and is provided as an argument in the next call to the callback function.

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

A function that accepts up to four arguments. The reduceRight method calls the callbackfn function one time for each element in the array.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reduceRight`](../../../GeneralName/classes/GeneralNames.md#reduceright)

#### Call Signature

> **reduceRight**(`callbackfn`, `initialValue`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Parameters

###### callbackfn

(`previousValue`, `currentValue`, `currentIndex`, `array`) => [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

###### initialValue

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reduceRight`](../../../GeneralName/classes/GeneralNames.md#reduceright)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reduceRight`](../../../GeneralName/classes/GeneralNames.md#reduceright)

---

### reverse()

> **reverse**(): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Reverses the elements in an array in place.
This method mutates the array and returns a reference to the same array.

#### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`reverse`](../../../GeneralName/classes/GeneralNames.md#reverse)

---

### shift()

> **shift**(): `undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

Removes the first element from an array and returns it.
If the array is empty, undefined is returned and the array is not modified.

#### Returns

`undefined` \| [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`shift`](../../../GeneralName/classes/GeneralNames.md#shift)

---

### slice()

> **slice**(`start?`, `end?`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

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

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`slice`](../../../GeneralName/classes/GeneralNames.md#slice)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`some`](../../../GeneralName/classes/GeneralNames.md#some)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`sort`](../../../GeneralName/classes/GeneralNames.md#sort)

---

### splice()

#### Call Signature

> **splice**(`start`, `deleteCount?`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Removes elements from an array and, if necessary, inserts new elements in their place, returning the deleted elements.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount?

`number`

The number of elements to remove.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

An array containing the elements that were deleted.

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`splice`](../../../GeneralName/classes/GeneralNames.md#splice)

#### Call Signature

> **splice**(`start`, `deleteCount`, ...`items`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Removes elements from an array and, if necessary, inserts new elements in their place, returning the deleted elements.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount

`number`

The number of elements to remove.

###### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Elements to insert into the array in place of the deleted elements.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

An array containing the elements that were deleted.

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`splice`](../../../GeneralName/classes/GeneralNames.md#splice)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this sequence to ASN.1 SEQUENCE structure.

#### Returns

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

An ASN.1 SEQUENCE containing all items in order

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toAsn1`](../../../GeneralName/classes/GeneralNames.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this sequence to DER format.

#### Returns

`Uint8Array`

The DER-encoded bytes of this sequence

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toDer`](../../../GeneralName/classes/GeneralNames.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this sequence.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toHumanString`](../../../GeneralName/classes/GeneralNames.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../../core/PkiBase/type-aliases/ToJson.md)\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../../core/PkiBase/type-aliases/ToJson.md)\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

A JSON-serializable representation of this array

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toJSON`](../../../GeneralName/classes/GeneralNames.md#tojson)

---

### toLocaleString()

#### Call Signature

> **toLocaleString**(): `string`

Returns a string representation of an array. The elements are converted to string using their toLocaleString methods.

##### Returns

`string`

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toLocaleString`](../../../GeneralName/classes/GeneralNames.md#tolocalestring)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toLocaleString`](../../../GeneralName/classes/GeneralNames.md#tolocalestring)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toPem`](../../../GeneralName/classes/GeneralNames.md#topem)

---

### toReversed()

> **toReversed**(): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Returns a copy of an array with its elements reversed.

#### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toReversed`](../../../GeneralName/classes/GeneralNames.md#toreversed)

---

### toSorted()

> **toSorted**(`compareFn?`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

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

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toSorted`](../../../GeneralName/classes/GeneralNames.md#tosorted)

---

### toSpliced()

#### Call Signature

> **toSpliced**(`start`, `deleteCount`, ...`items`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Copies an array and removes elements and, if necessary, inserts new elements in their place. Returns the copied array.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount

`number`

The number of elements to remove.

###### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Elements to insert into the copied array in place of the deleted elements.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

The copied array.

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toSpliced`](../../../GeneralName/classes/GeneralNames.md#tospliced)

#### Call Signature

> **toSpliced**(`start`, `deleteCount?`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Copies an array and removes elements while returning the remaining elements.

##### Parameters

###### start

`number`

The zero-based location in the array from which to start removing elements.

###### deleteCount?

`number`

The number of elements to remove.

##### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

A copy of the original array with the remaining elements.

##### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toSpliced`](../../../GeneralName/classes/GeneralNames.md#tospliced)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toString`](../../../GeneralName/classes/GeneralNames.md#tostring)

---

### unshift()

> **unshift**(...`items`): `number`

Inserts new elements at the start of an array, and returns the new length of the array.

#### Parameters

##### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Elements to insert at the start of the array.

#### Returns

`number`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`unshift`](../../../GeneralName/classes/GeneralNames.md#unshift)

---

### values()

> **values**(): `ArrayIterator`\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

Returns an iterable of values in the array

#### Returns

`ArrayIterator`\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`values`](../../../GeneralName/classes/GeneralNames.md#values)

---

### with()

> **with**(`index`, `value`): [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

Copies an array, then overwrites the value at the provided index with the
given value. If the index is negative, then it replaces from the end
of the array.

#### Parameters

##### index

`number`

The index of the value to overwrite. If the index is
negative, then it replaces from the end of the array.

##### value

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

The value to write into the copied array.

#### Returns

[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

The copied array with the updated value.

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`with`](../../../GeneralName/classes/GeneralNames.md#with)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`from`](../../../GeneralName/classes/GeneralNames.md#from)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`from`](../../../GeneralName/classes/GeneralNames.md#from)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`from`](../../../GeneralName/classes/GeneralNames.md#from)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`from`](../../../GeneralName/classes/GeneralNames.md#from)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SubjectAltName`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`SubjectAltName`

#### Overrides

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`fromAsn1`](../../../GeneralName/classes/GeneralNames.md#fromasn1)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`fromAsync`](../../../GeneralName/classes/GeneralNames.md#fromasync)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`fromAsync`](../../../GeneralName/classes/GeneralNames.md#fromasync)

---

### isArray()

> `static` **isArray**(`arg`): `arg is any[]`

#### Parameters

##### arg

`any`

#### Returns

`arg is any[]`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`isArray`](../../../GeneralName/classes/GeneralNames.md#isarray)

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

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`of`](../../../GeneralName/classes/GeneralNames.md#of)
