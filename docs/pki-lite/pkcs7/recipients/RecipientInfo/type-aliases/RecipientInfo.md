[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [pkcs7/recipients/RecipientInfo](../README.md) / RecipientInfo

# Type Alias: RecipientInfo

> **RecipientInfo** = [`KeyTransRecipientInfo`](../../KeyTransRecipientInfo/classes/KeyTransRecipientInfo.md) \| [`KeyAgreeRecipientInfo`](../../KeyAgreeRecipientInfo/classes/KeyAgreeRecipientInfo.md) \| [`KEKRecipientInfo`](../../KEKRecipientInfo/classes/KEKRecipientInfo.md) \| [`PasswordRecipientInfo`](../../PasswordRecipientInfo/classes/PasswordRecipientInfo.md) \| [`OtherRecipientInfo`](../../OtherRecipientInfo/classes/OtherRecipientInfo.md)

Represents a CMS RecipientInfo structure as defined in RFC 5652.

## Asn

```asn
RecipientInfo ::= CHOICE {
  ktri KeyTransRecipientInfo,
  kari [1] KeyAgreeRecipientInfo,
  kekri [2] KEKRecipientInfo,
  pwri [3] PasswordRecipientInfo,
  ori [4] OtherRecipientInfo
}
```
