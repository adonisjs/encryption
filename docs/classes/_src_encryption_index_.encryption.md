**[@adonisjs/encryption](../README.md)**

[Globals](../globals.md) › [&quot;src/Encryption/index&quot;](../modules/_src_encryption_index_.md) › [Encryption](_src_encryption_index_.encryption.md)

# Class: Encryption

Encryption class uses `AES-256` to encrypt raw values using `Objects`,
`Arrays` and even `Date` objects. When `hmac=true`, an HMAC is
generated with `sha256` encryption.

## Hierarchy

* **Encryption**

## Implements

* EncryptionContract

## Index

### Constructors

* [constructor](_src_encryption_index_.encryption.md#constructor)

### Methods

* [base64Decode](_src_encryption_index_.encryption.md#base64decode)
* [base64Encode](_src_encryption_index_.encryption.md#base64encode)
* [child](_src_encryption_index_.encryption.md#child)
* [decrypt](_src_encryption_index_.encryption.md#decrypt)
* [encrypt](_src_encryption_index_.encryption.md#encrypt)

## Constructors

###  constructor

\+ **new Encryption**(`_secret`: string, `_options?`: Partial‹EncryptionConfigContract›): *[Encryption](_src_encryption_index_.encryption.md)*

**Parameters:**

Name | Type |
------ | ------ |
`_secret` | string |
`_options?` | Partial‹EncryptionConfigContract› |

**Returns:** *[Encryption](_src_encryption_index_.encryption.md)*

## Methods

###  base64Decode

▸ **base64Decode**(`encoded`: string | Buffer, `encoding`: BufferEncoding): *string*

Base64 decode a previously encoded string or Buffer.

**Parameters:**

Name | Type | Default |
------ | ------ | ------ |
`encoded` | string &#124; Buffer | - |
`encoding` | BufferEncoding | "utf-8" |

**Returns:** *string*

___

###  base64Encode

▸ **base64Encode**(`arrayBuffer`: ArrayBuffer | SharedArrayBuffer): *string*

Base64 encode Buffer or string

**Parameters:**

Name | Type |
------ | ------ |
`arrayBuffer` | ArrayBuffer &#124; SharedArrayBuffer |

**Returns:** *string*

▸ **base64Encode**(`data`: string, `encoding?`: BufferEncoding): *string*

**Parameters:**

Name | Type |
------ | ------ |
`data` | string |
`encoding?` | BufferEncoding |

**Returns:** *string*

___

###  child

▸ **child**(`options?`: Partial‹EncryptionConfigContract›): *[Encryption](_src_encryption_index_.encryption.md)*

Returns a custom instance of [Encryption](_src_encryption_index_.encryption.md) class with custom
configuration

**Parameters:**

Name | Type |
------ | ------ |
`options?` | Partial‹EncryptionConfigContract› |

**Returns:** *[Encryption](_src_encryption_index_.encryption.md)*

___

###  decrypt

▸ **decrypt**(`payload`: string): *any*

Decrypt existing encrypted value. Returns `null`, when unable to
decrypt.

**Parameters:**

Name | Type |
------ | ------ |
`payload` | string |

**Returns:** *any*

___

###  encrypt

▸ **encrypt**(`payload`: any): *string*

Encrypts value with `AES-256` encryption. HMAC is disabled by default for
returning shorter output. Feel free to grab a [[newInstance]] of the
encryption class with `hmac=true`.

**Parameters:**

Name | Type |
------ | ------ |
`payload` | any |

**Returns:** *string*