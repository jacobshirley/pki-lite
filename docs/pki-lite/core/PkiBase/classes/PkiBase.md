[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / PkiBase

# Abstract Class: PkiBase\<T\>

Base class for all PKI objects in the library.

Provides common functionality for ASN.1 encoding/decoding, PEM formatting,
DER serialization, and object comparison. All PKI structures extend this class
to ensure consistent behavior across the library.

## Extended by

- [`OtherRevInfo`](../../../adobe/OtherRevInfo/classes/OtherRevInfo.md)
- [`RevocationInfoArchival`](../../../adobe/RevocationInfoArchival/classes/RevocationInfoArchival.md)
- [`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)
- [`CCMParameters`](../../../algorithms/CCMParameters/classes/CCMParameters.md)
- [`GCMParameters`](../../../algorithms/GCMParameters/classes/GCMParameters.md)
- [`RSAESOAEPParams`](../../../algorithms/RSAESOAEPParams/classes/RSAESOAEPParams.md)
- [`RSASSAPSSParams`](../../../algorithms/RSASSAPSSParams/classes/RSASSAPSSParams.md)
- [`Any`](../../../asn1/Any/classes/Any.md)
- [`BMPString`](../../../asn1/BMPString/classes/BMPString.md)
- [`BitString`](../../../asn1/BitString/classes/BitString.md)
- [`Boolean`](../../../asn1/Boolean/classes/Boolean.md)
- [`GeneralizedTime`](../../../asn1/GeneralizedTime/classes/GeneralizedTime.md)
- [`IA5String`](../../../asn1/IA5String/classes/IA5String.md)
- [`Integer`](../../../asn1/Integer/classes/Integer.md)
- [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)
- [`OctetString`](../../../asn1/OctetString/classes/OctetString.md)
- [`PrintableString`](../../../asn1/PrintableString/classes/PrintableString.md)
- [`TeletexString`](../../../asn1/TeletexString/classes/TeletexString.md)
- [`UTCTime`](../../../asn1/UTCTime/classes/UTCTime.md)
- [`GeneralizedTime`](../../../asn1/UTCTime/classes/GeneralizedTime.md)
- [`UTF8String`](../../../asn1/UTF8String/classes/UTF8String.md)
- [`UniversalString`](../../../asn1/UniversalString/classes/UniversalString.md)
- [`ECDSASignature`](../../../keys/ECDSASignature/classes/ECDSASignature.md)
- [`ECPrivateKey`](../../../keys/ECPrivateKey/classes/ECPrivateKey.md)
- [`EncryptedPrivateKeyInfo`](../../../keys/EncryptedPrivateKeyInfo/classes/EncryptedPrivateKeyInfo.md)
- [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)
- [`RSAPrivateKey`](../../../keys/RSAPrivateKey/classes/RSAPrivateKey.md)
- [`RSAPublicKey`](../../../keys/RSAPublicKey/classes/RSAPublicKey.md)
- [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)
- [`BasicOCSPResponse`](../../../ocsp/BasicOCSPResponse/classes/BasicOCSPResponse.md)
- [`CertID`](../../../ocsp/CertID/classes/CertID.md)
- [`CertStatus`](../../../ocsp/CertStatus/classes/CertStatus.md)
- [`OCSPRequest`](../../../ocsp/OCSPRequest/classes/OCSPRequest.md)
- [`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)
- [`OCSPResponseStatus`](../../../ocsp/OCSPResponseStatus/classes/OCSPResponseStatus.md)
- [`OCSPSignature`](../../../ocsp/OCSPSignature/classes/OCSPSignature.md)
- [`Request`](../../../ocsp/Request/classes/Request.md)
- [`ResponseBytes`](../../../ocsp/ResponseBytes/classes/ResponseBytes.md)
- [`ResponseData`](../../../ocsp/ResponseData/classes/ResponseData.md)
- [`RevokedInfo`](../../../ocsp/RevokedInfo/classes/RevokedInfo.md)
- [`SingleResponse`](../../../ocsp/SingleResponse/classes/SingleResponse.md)
- [`TBSRequest`](../../../ocsp/TBSRequest/classes/TBSRequest.md)
- [`CertBag`](../../../pkcs12/CertBag/classes/CertBag.md)
- [`DigestInfo`](../../../pkcs12/DigestInfo/classes/DigestInfo.md)
- [`MacData`](../../../pkcs12/MacData/classes/MacData.md)
- [`PFX`](../../../pkcs12/PFX/classes/PFX.md)
- [`SafeBag`](../../../pkcs12/SafeBag/classes/SafeBag.md)
- [`PBEParameter`](../../../pkcs5/PBEParameter/classes/PBEParameter.md)
- [`PBES2Params`](../../../pkcs5/PBES2Params/classes/PBES2Params.md)
- [`PBKDF2Params`](../../../pkcs5/PBKDF2Params/classes/PBKDF2Params.md)
- [`AuthEnvelopedData`](../../../pkcs7/AuthEnvelopedData/classes/AuthEnvelopedData.md)
- [`AuthenticatedData`](../../../pkcs7/AuthenticatedData/classes/AuthenticatedData.md)
- [`ContentInfo`](../../../pkcs7/ContentInfo/classes/ContentInfo.md)
- [`Data`](../../../pkcs7/Data/classes/Data.md)
- [`DigestedData`](../../../pkcs7/DigestedData/classes/DigestedData.md)
- [`EncapsulatedContentInfo`](../../../pkcs7/EncapsulatedContentInfo/classes/EncapsulatedContentInfo.md)
- [`EncryptedContentInfo`](../../../pkcs7/EncryptedContentInfo/classes/EncryptedContentInfo.md)
- [`EncryptedData`](../../../pkcs7/EncryptedData/classes/EncryptedData.md)
- [`EnvelopedData`](../../../pkcs7/EnvelopedData/classes/EnvelopedData.md)
- [`IssuerAndSerialNumber`](../../../pkcs7/IssuerAndSerialNumber/classes/IssuerAndSerialNumber.md)
- [`SignedData`](../../../pkcs7/SignedData/classes/SignedData.md)
- [`SignerInfo`](../../../pkcs7/SignerInfo/classes/SignerInfo.md)
- [`OtherRevocationInfoFormat`](../../../revocation/OtherRevocationInfoFormat/classes/OtherRevocationInfoFormat.md)
- [`MessageImprint`](../../../timestamp/MessageImprint/classes/MessageImprint.md)
- [`TimeStampReq`](../../../timestamp/TimeStampReq/classes/TimeStampReq.md)
- [`PKIFreeText`](../../../timestamp/TimeStampResp/classes/PKIFreeText.md)
- [`PKIStatusInfo`](../../../timestamp/TimeStampResp/classes/PKIStatusInfo.md)
- [`TimeStampResp`](../../../timestamp/TimeStampResp/classes/TimeStampResp.md)
- [`Attribute`](../../../x509/Attribute/classes/Attribute.md)
- [`AttributeTypeAndValue`](../../../x509/AttributeTypeAndValue/classes/AttributeTypeAndValue.md)
- [`CRLReason`](../../../x509/CRLReason/classes/CRLReason.md)
- [`Certificate`](../../../x509/Certificate/classes/Certificate.md)
- [`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md)
- [`CertificateRequest`](../../../x509/CertificateRequest/classes/CertificateRequest.md)
- [`CertificateRequestInfo`](../../../x509/CertificateRequestInfo/classes/CertificateRequestInfo.md)
- [`Extension`](../../../x509/Extension/classes/Extension.md)
- [`AnotherName`](../../../x509/GeneralName/classes/AnotherName.md)
- [`EDIPartyName`](../../../x509/GeneralName/classes/EDIPartyName-1.md)
- [`IssuerSerial`](../../../x509/IssuerSerial/classes/IssuerSerial.md)
- [`PolicyQualifierInfo`](../../../x509/PolicyInformation/classes/PolicyQualifierInfo.md)
- [`PolicyInformation`](../../../x509/PolicyInformation/classes/PolicyInformation.md)
- [`ReasonFlags`](../../../x509/ReasonFlags/classes/ReasonFlags.md)
- [`RevokedCertificate`](../../../x509/RevokedCertificate/classes/RevokedCertificate.md)
- [`TBSCertList`](../../../x509/TBSCertList/classes/TBSCertList.md)
- [`TBSCertificate`](../../../x509/TBSCertificate/classes/TBSCertificate.md)
- [`Validity`](../../../x509/Validity/classes/Validity.md)
- [`KEKIdentifier`](../../../pkcs7/recipients/KEKIdentifier/classes/KEKIdentifier.md)
- [`KEKRecipientInfo`](../../../pkcs7/recipients/KEKRecipientInfo/classes/KEKRecipientInfo.md)
- [`KeyAgreeRecipientInfo`](../../../pkcs7/recipients/KeyAgreeRecipientInfo/classes/KeyAgreeRecipientInfo.md)
- [`KeyTransRecipientInfo`](../../../pkcs7/recipients/KeyTransRecipientInfo/classes/KeyTransRecipientInfo.md)
- [`OriginatorInfo`](../../../pkcs7/recipients/OriginatorInfo/classes/OriginatorInfo.md)
- [`OriginatorPublicKey`](../../../pkcs7/recipients/OriginatorPublicKey/classes/OriginatorPublicKey.md)
- [`OtherKeyAttribute`](../../../pkcs7/recipients/OtherKeyAttribute/classes/OtherKeyAttribute.md)
- [`OtherRecipientInfo`](../../../pkcs7/recipients/OtherRecipientInfo/classes/OtherRecipientInfo.md)
- [`PasswordRecipientInfo`](../../../pkcs7/recipients/PasswordRecipientInfo/classes/PasswordRecipientInfo.md)
- [`RecipientEncryptedKey`](../../../pkcs7/recipients/RecipientEncryptedKey/classes/RecipientEncryptedKey.md)
- [`RecipientKeyIdentifier`](../../../pkcs7/recipients/RecipientKeyIdentifier/classes/RecipientKeyIdentifier.md)
- [`AttributeCertificate`](../../../x509/attribute-certs/AttributeCertificate/classes/AttributeCertificate.md)
- [`Holder`](../../../x509/attribute-certs/AttributeCertificateInfo/classes/Holder.md)
- [`AttCertIssuer`](../../../x509/attribute-certs/AttributeCertificateInfo/classes/AttCertIssuer.md)
- [`AttributeCertificateInfo`](../../../x509/attribute-certs/AttributeCertificateInfo/classes/AttributeCertificateInfo.md)
- [`AttributeCertificateInfoV1`](../../../x509/attribute-certs/AttributeCertificateInfoV1/classes/AttributeCertificateInfoV1.md)
- [`AttributeCertificateV1`](../../../x509/attribute-certs/AttributeCertificateV1/classes/AttributeCertificateV1.md)
- [`OtherRevVals`](../../../x509/attributes/RevocationValues/classes/OtherRevVals.md)
- [`RevocationValues`](../../../x509/attributes/RevocationValues/classes/RevocationValues.md)
- [`SigPolicyQualifierInfo`](../../../x509/attributes/SignaturePolicyIdentifier/classes/SigPolicyQualifierInfo.md)
- [`OtherHashAlgAndValue`](../../../x509/attributes/SignaturePolicyIdentifier/classes/OtherHashAlgAndValue.md)
- [`SignaturePolicyId`](../../../x509/attributes/SignaturePolicyIdentifier/classes/SignaturePolicyId.md)
- [`SignerLocation`](../../../x509/attributes/SignerLocation/classes/SignerLocation.md)
- [`ESSCertID`](../../../x509/attributes/SigningCertificate/classes/ESSCertID.md)
- [`SigningCertificate`](../../../x509/attributes/SigningCertificate/classes/SigningCertificate.md)
- [`ESSCertIDv2`](../../../x509/attributes/SigningCertificateV2/classes/ESSCertIDv2.md)
- [`SigningCertificateV2`](../../../x509/attributes/SigningCertificateV2/classes/SigningCertificateV2.md)
- [`AccessDescription`](../../../x509/extensions/AuthorityInfoAccess/classes/AccessDescription.md)
- [`AuthorityKeyIdentifier`](../../../x509/extensions/AuthorityKeyIdentifier/classes/AuthorityKeyIdentifier.md)
- [`BasicConstraints`](../../../x509/extensions/BasicConstraints/classes/BasicConstraints.md)
- [`DistributionPoint`](../../../x509/extensions/CRLDistributionPoints/classes/DistributionPoint.md)
- [`KeyUsage`](../../../x509/extensions/KeyUsage/classes/KeyUsage.md)
- [`GeneralSubtree`](../../../x509/extensions/NameConstraints/classes/GeneralSubtree.md)
- [`NameConstraints`](../../../x509/extensions/NameConstraints/classes/NameConstraints.md)
- [`ExtendedCertificate`](../../../x509/legacy/ExtendedCertificate/classes/ExtendedCertificate.md)
- [`ExtendedCertificateInfo`](../../../x509/legacy/ExtendedCertificateInfo/classes/ExtendedCertificateInfo.md)
- [`OtherCertificateFormat`](../../../x509/legacy/OtherCertificateFormat/classes/OtherCertificateFormat.md)

## Type Parameters

### T

`T` _extends_ `object` = `any`

The specific PKI type that extends this base class

## Constructors

### Constructor

> **new PkiBase**\<`T`\>(): `PkiBase`\<`T`\>

#### Returns

`PkiBase`\<`T`\>

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this PKI object with another for equality.
Two objects are considered equal if their DER encodings are identical.

#### Parameters

##### other

`PkiBase`\<`any`\>

The other PKI object to compare with

#### Returns

`boolean`

true if the objects are equal, false otherwise

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this object as a different PKI type.
Useful for converting between related PKI structures.

#### Type Parameters

##### T

`T`

The target type to parse as

#### Parameters

##### type

[`ParseableAsn1`](../type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

---

### toAsn1()

> `abstract` **toAsn1**(): [`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

The ASN.1 representation of this object

---

### toDer()

> **toDer**(): `Uint8Array<ArrayBuffer>`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array<ArrayBuffer>`

The DER-encoded bytes of this object

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this object.
By default, returns the same as toString(), but subclasses can override
for more user-friendly output.

#### Returns

`string`

A human-readable string representation

---

### toJSON()

> **toJSON**(): [`ToJson`](../type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging
