# crypto stream
[![tests](https://img.shields.io/github/actions/workflow/status/mycelial-systems/crypto-stream/nodejs.yml?style=flat-square)](https://github.com/mycelial-systems/crypto-stream/actions/workflows/nodejs.yml)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![types](https://img.shields.io/npm/types/@vanishing.page/crypto-stream?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@vanishing.page/crypto-stream?cache-control=no-cache)](https://packagephobia.com/result?p=@vanishing.page/crypto-stream)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Streaming encryption for the browser, based on
[Encrypted Content-Encoding for HTTP (RFC 8188)](https://tools.ietf.org/html/rfc8188)

This uses the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Fork](#fork)
- [Example](#example)
  * [Example With Blobs](#example-with-blobs)
- [Seek](#seek)
- [API](#api)
  * [`new Keychain([key, [options]])`](#new-keychainkey-options)
  * [`Keychain.AuthHeader(secretKey, salt)`](#keychainauthheadersecretkey-salt)
  * [`Keychain.Header(writeToken)`](#keychainheaderwritetoken)
  * [`keychain.key`](#keychainkey)
  * [`keychain.keyB64`](#keychainkeyb64)
  * [`keychain.salt`](#keychainsalt)
  * [`keychain.saltB64`](#keychainsaltb64)
  * [`keychain.authToken()`](#keychainauthtoken)
  * [`keychain.authTokenB64()`](#keychainauthtokenb64)
  * [`keychain.authHeader([tokenString])`](#keychainauthheadertokenstring)
  * [`keychain.setAuthToken(authToken)`](#keychainsetauthtokenauthtoken)
  * [`keychain.encryptStream(stream[, opts])`](#keychainencryptstreamstream-opts)
  * [`keychain.contentDigest(content)`](#keychaincontentdigestcontent)
  * [`keychain.header(opts)`](#keychainheaderopts)
  * [`keychain.encryptRecord(seq, plaintext, opts)`](#keychainencryptrecordseq-plaintext-opts)
  * [`keychain.decryptStream(encryptedStream[, opts])`](#keychaindecryptstreamencryptedstream-opts)
  * [`keychain.decryptStreamRange(offset, length, totalEncryptedLength[, opts])`](#keychaindecryptstreamrangeoffset-length-totalencryptedlength-opts)
  * [`keychain.encryptMeta(meta)`](#keychainencryptmetameta)
  * [`keychain.decryptMeta(ivEncryptedMeta)`](#keychaindecryptmetaivencryptedmeta)
  * [`keychain.encryptBytes(bytes[, opts])`](#keychainencryptbytesbytes-opts)
  * [`keychain.decryptBytes(bytes[, opts])`](#keychaindecryptbytesbytes-opts)
  * [`plaintextSize(encryptedSize)`](#plaintextsizeencryptedsize)
  * [`encryptedSize(plaintextSize)`](#encryptedsizeplaintextsize)
- [Reproducible & record-addressable encryption](#reproducible--record-addressable-encryption)
  * [Two-pass flow: hash, then encrypt](#two-pass-flow-hash-then-encrypt)
  * [Low-level ECE building blocks](#low-level-ece-building-blocks)
- [credits](#credits)

<!-- tocstop -->

</details>

## Install

```sh
npm i -S @vanishing.page/crypto-stream
```

## Fork

This is a fork of
[SocketDev/wormhole-crypto](https://github.com/SocketDev/wormhole-crypto).
Thanks [@SocketDev](https://github.com/SocketDev) team for working in the
world of open source.

## Example

```js
import { Keychain } from '@vanishing.page/crypto-stream'

// Create a new keychain. Since no arguments are specified, the key and salt
// are generated.
const keychain = new Keychain()

// Get a WHATWG stream somehow, from fetch(), from a Blob(), etc.
const stream = getStream(/* ... */)

// Create an encrypted version of that stream
const encryptedStream = await keychain.encryptStream(stream)

// Normally you'd now use `encryptedStream`, e.g. in fetch(), etc.
// For this example, we'll just decrypt the stream immediately
const plaintextStream = await keychain.decryptStream(encryptedStream)

// Now, you can use `plaintextStream` and it will be identical
// to if you had used `stream`.
```

### Example With Blobs

See [./example](./example/index.ts) for a version that uses blobs + a
local `vite` server.

```js
import { Keychain } from '@vanishing.page/crypto-stream'

// Stream decryption requires the same main key. The encrypted stream
// header carries the ECE salt and record size.
const keychain = new Keychain(key)

const response = await fetch(imgUrl)
const decryptedStream = await keychain.decryptStream(response.body)
const decryptedResponse = new Response(decryptedStream)
const blobUrl = window.URL.createObjectURL(await decryptedResponse.blob())

// ...

function Component () {
    return html`<img src="${blobUrl}" />`
}
```

## Seek

`crypto-stream` can seek on both sides of the cipher.

Reads use
[`decryptStreamRange`](#keychaindecryptstreamrangeoffset-length-totalencryptedlength-opts),
which decrypts an arbitrary byte range without reading the whole
ciphertext.

Writes use *reproducible, record-addressable* encryption. The same plaintext
always encrypts to identical bytes, and you can regenerate any single record
on demand without re-encrypting the rest. That is what lets a peer seed a
large file (for example, over WebRTC) without buffering the whole ciphertext.
Hash the content once, then hand out individual records as they are requested.

```js
import { Keychain } from '@vanishing.page/crypto-stream'
import {
    recordPlaintextSize,
    recordCount
} from '@vanishing.page/crypto-stream/ece'

const keychain = new Keychain()
const data = new TextEncoder().encode('the quick brown fox')
const rs = 1024  // record size; transport chunks line up with records

// 1. Hash pass. The salt is derived from this digest, so it is bound
//    to exactly this content (no AES-GCM nonce reuse).
const digest = await keychain.contentDigest(data)

// 2. Reproducible whole-stream encrypt. Re-encrypting `data` with the
//    same digest yields byte-identical output.
const encrypted = await keychain.encryptStream(new Response(data).body, {
    contentDigest: digest,
    recordSize: rs
})

// 3. Record-addressable: rebuild any single record on demand. The full
//    ciphertext is `header || rec0 || rec1 || ... || recLast`.
const head = await keychain.header({ contentDigest: digest, recordSize: rs })

const max = recordPlaintextSize(rs)  // plaintext bytes per record
const count = recordCount(data.length, rs)  // number of data records

const i = 0
const slice = data.subarray(i * max, (i + 1) * max)
const record = await keychain.encryptRecord(i, slice, {
    isLast: i === count - 1,
    contentDigest: digest,
    recordSize: rs
})
// `head || record` equals the first record of `encrypted`, byte for byte.
```

See
[Reproducible & record-addressable encryption](#reproducible--record-addressable-encryption)
for the safety model (why the salt is derived from the content) and the
low-level building blocks.

## API

### `new Keychain([key, [options]])`

```ts
type KeychainOptions = {
    salt?:string|Uint8Array|null
    encoding?:uint8arrays.SupportedEncodings
}

constructor (
    key?:string|Uint8Array|null,
    options?:KeychainOptions|string|Uint8Array|null
)
```

Type: `Class`

Returns: `Keychain`

Create a new keychain object. The keychain can be used to create encryption
streams, decryption streams, and to encrypt or decrypt a "metadata" buffer.

#### `key`

Type: `Uint8Array | string | null`

Default: `null`

The main key. This should be 16 or 32 bytes in length. If a `string` is
given, then it should be a base64url-encoded string by default. To use another
`uint8arrays` string encoding, pass `options.encoding`. If the argument is
`null`, then a key will be automatically generated.

#### `options`

Type: `KeychainOptions | string | Uint8Array | null`

Default: `null`

Constructor options. For backwards compatibility, the second argument may still
be a salt string or `Uint8Array` directly.

#### `options.salt`

Type: `Uint8Array | string | null`

Default: `null`

The Keychain salt. This should be 16 bytes in length. If a `string` is
given, then it should be a base64url-encoded string. If this
argument is `null`, then a salt will be automatically generated. This value
is used for auth and metadata derivation, not as the ECE stream header salt.

#### `options.encoding`

Type: `uint8arrays.SupportedEncodings`

Default: `'base64url'`

The string encoding to use when `key` is a string. This option is ignored when
`key` is a `Uint8Array` or nullish.

### `Keychain.AuthHeader(secretKey, salt)`

```ts
static async AuthHeader (
    secretKey:string,
    salt:string|Uint8Array
):Promise<string>
```

Static equivalent of [`keychain.authHeader()`](#keychainauthheadertokenstring),
for callers that have an encoded key and salt but no `Keychain` instance.
Derives the auth token from `secretKey` and `salt` and returns the same
`Bearer sync-v1 ${authTokenB64}` header value.

#### `secretKey`

Type: `string`

The main key, as a base64url-encoded string.

#### `salt`

Type: `string | Uint8Array`

The salt used to derive the authentication token. String salts may be
base64url-encoded.

### `Keychain.Header(writeToken)`

```ts
static Header (writeToken:string):string
```

Format a token as the HTTP header value: `Bearer sync-v1 ${writeToken}`.
Used internally by `Keychain.AuthHeader` and `keychain.authHeader`, and
useful on its own for formatting a server-issued writer token.

#### `writeToken`

Type: `string`

A base64url-encoded token.

### `keychain.key`

```ts
key:Uint8Array
```

The main key.

### `keychain.keyB64`

```ts
keyB64:string
```

The main key as a base64url-encoded string.

### `keychain.salt`

```ts
salt:Uint8Array
```

The Keychain salt.

Implementation note: The salt is used to derive the (internal) metadata key and
authentication token. It is separate from the ECE stream salt, which is
written into each encrypted stream's content-coding header.

### `keychain.saltB64`

```ts
saltB64:string
```
The salt as a base64url-encoded string.

### `keychain.authToken()`
```ts
authToken ():Promise<Uint8Array>
```

Returns the authentication token. By default, the authentication token is
automatically derived from the main key using HKDF SHA-256.

The authentication token can be used to communicate with the server and
prove that the client has permission to fetch some data. Without a valid
authentication token, the server can reject the request.

Since the authentication token is derived from the main key, the client would
present it to the server as a "reader token" to prove that it is in possession
of the main key without revealing the main key to the server.

For destructive operations, the client should instead
present a "writer token", which is not derived from the main key but is provided
by the server. 

### `keychain.authTokenB64()`

```ts
authTokenB64 ():Promise<string>
```

Returns the authentication token as a base64url-encoded string.

### `keychain.authHeader([tokenString])`

```ts
authHeader (tokenString?:string):Promise<string>
// => `Bearer sync-v1 ${tokenString ?? authTokenB64}`
```

Returns a `Promise` that resolves to the HTTP header value to be provided to
the server, as a base64url string. It contains the authentication token.

#### `tokenString`

Type: `string`

Optional. A base64url-encoded token to use instead of the keychain's own
`authTokenB64`. Useful for presenting a server-issued "writer token"
instead of the reader token derived from the main key.

### `keychain.setAuthToken(authToken)`

```ts
setAuthToken (authToken:string|Uint8Array|null):void
```

Update the keychain authentication token to the given `authToken`.

#### `authToken`

Type: `Uint8Array | string | null`

Default: `null`

The authentication token. This should be 16 bytes in length. If a `string` is
given, then it should be a base64url-encoded string. If this argument is `null`,
then an authentication token will be automatically generated.

### `keychain.encryptStream(stream[, opts])`

```ts
encryptStream (
    stream:ReadableStream,
    opts?:{ contentDigest?, recordSize? }
):Promise<ReadableStream>
```

Type: `Function`

Returns: `Promise<ReadableStream>`

Returns a `Promise` that resolves to a `ReadableStream` encryption stream that
consumes the data in `stream` and returns an encrypted version. Data is
encrypted with [Encrypted Content-Encoding for HTTP (RFC 8188)](https://tools.ietf.org/html/rfc8188).

If `opts.contentDigest` is provided, the salt is derived from the digest,
making the output reproducible — the same plaintext always produces
identical ciphertext. Without options, a fresh random salt is used
(default behavior; not reproducible).

#### `stream`

Type: `ReadableStream`

A WHATWG readable stream used as a data source for the encrypted stream.

#### `opts`

Type: `{ contentDigest?, recordSize? }`

Optional encryption options.

##### `contentDigest`

Type: `Uint8Array`

SHA-256 digest of the plaintext (from `keychain.contentDigest()`).
When provided, enables reproducible encryption by deriving the salt
from the digest internally.

##### `recordSize`

Type: `number`

ECE record size in bytes (default `RECORD_SIZE` = 65536). Record size
affects output size and encryption granularity.

### `keychain.contentDigest(content)`

```ts
contentDigest (
    content:ReadableStream<Uint8Array>|Uint8Array|Blob
):Promise<Uint8Array>
```

Type: `Function`

Returns: `Promise<Uint8Array>`

Returns a 32-byte SHA-256 digest of the plaintext. Use this digest as
the input to `encryptStream`, `header`, and `encryptRecord` to enable
reproducible encryption. Accepts a stream, byte array, or Blob; streams
and Blobs are drained into memory before hashing.

#### `content`

Type: `ReadableStream<Uint8Array> | Uint8Array | Blob`

The plaintext to hash.

### `keychain.header(opts)`

```ts
header (opts:{ contentDigest, recordSize? }):Promise<Uint8Array>
```

Type: `Function`

Returns: `Promise<Uint8Array>`

Returns the 21-byte ECE header for content identified by the digest.
The salt is derived internally from the content digest, so this never
exposes a raw salt. The header is byte-identical to the header that
`encryptStream` with the same options emits.

#### `opts`

Type: `{ contentDigest, recordSize? }`

Required options.

##### `contentDigest`

Type: `Uint8Array`

SHA-256 digest of the plaintext (from `keychain.contentDigest()`).

##### `recordSize`

Type: `number`

ECE record size in bytes (default `RECORD_SIZE` = 65536).

### `keychain.encryptRecord(seq, plaintext, opts)`

```ts
encryptRecord (
    seq:number,
    plaintext:Uint8Array,
    opts:{
        isLast:boolean,
        contentDigest:Uint8Array,
        recordSize?:number
    }
):Promise<Uint8Array>
```

Type: `Function`

Returns: `Promise<Uint8Array>`

Encrypts a single ECE record by index. The result is byte-identical to
record `seq` of `encryptStream` with the same content and options. The
salt is derived from the content digest internally.

Non-final records must be exactly `recordPlaintextSize(recordSize)` bytes;
the final record must be less than or equal to that. The low-level ECE
functions throw if violated.

#### `seq`

Type: `number`

Zero-based record index (0, 1, 2, ...).

#### `plaintext`

Type: `Uint8Array`

The record's plaintext data.

#### `opts`

Type: `{ isLast, contentDigest, recordSize? }`

Required options.

##### `isLast`

Type: `boolean`

Whether this is the final record of the content.

##### `contentDigest`

Type: `Uint8Array`

SHA-256 digest of the entire plaintext (from `keychain.contentDigest()`).

##### `recordSize`

Type: `number`

ECE record size in bytes (default `RECORD_SIZE` = 65536). Must match
the record size used for the header and other records.

### `keychain.decryptStream(encryptedStream[, opts])`

```ts
decryptStream (
    encryptedStream:ReadableStream<Uint8Array>,
    opts?:{ recordSize?:number }
):Promise<ReadableStream<Uint8Array>>
```

Type: `Function`

Returns: `Promise<ReadableStream>`

Returns a `Promise` that resolves to a `ReadableStream` decryption stream that
consumes the data in `encryptedStream` and returns a plaintext version.

#### `encryptedStream`

Type: `ReadableStream`

A WHATWG readable stream used as a data source for the plaintext stream.

#### `opts`

Type: `{ recordSize? }`

Optional validation hint. Sequential stream decryption reads the ECE salt
and record size from the encrypted stream's RFC 8188 content-coding header.
If `recordSize` is provided, decryption fails when it does not match the
header.

### `keychain.decryptStreamRange(offset, length, totalEncryptedLength[, opts])`

```ts
decryptStreamRange (
    offset:number,
    length:number,
    totalEncryptedLength:number,
    opts?:{ recordSize?:number }
):Promise<{
    ranges:{ offset:number, length:number }[],
    decrypt:(streams:ReadableStream[])=>ReadableStream
}>
```

Returns a `Promise` that resolves to a object containing `ranges`, which is
an array of objects containing `offset` and `length` integers specifying the
encrypted byte ranges that are needed to decrypt the client's specified range,
and a `decrypt` function.

Once the client has gathered a stream for each byte range in `ranges`,
the client should call `decrypt(streams)`, where `streams` is an array of
`ReadableStream` objects, one for each of the requested ranges. `decrypt`
will then return a `ReadableStream` containing the plaintext data for the
client's desired byte range.

#### `offset`

Type: `number`

Byte offset into the plaintext to start reading from.

#### `length`

Type: `number`

Number of plaintext bytes to read.

#### `totalEncryptedLength`

Type: `number`

Total length, in bytes, of the encrypted stream.

#### `opts`

Type: `{ recordSize? }`

Pass the same `recordSize` that was used to encrypt the stream; defaults to
`RECORD_SIZE` (65536). Range decryption needs this before reading the body
so it can calculate encrypted byte ranges. Sequential `decryptStream` reads
the record size from the encrypted stream header. This helper is intended
for streams produced by this package, which writes empty `keyid` headers.

### `keychain.encryptMeta(meta)`

```ts
encryptMeta (meta:Uint8Array):Promise<Uint8Array>
```

Returns a `Promise` that resolves to an encrypted version of `meta`. The
metadata is encrypted with AES-GCM.

Implementation note: The metadata key is automatically derived from the main
key using HKDF SHA-256. The value is not user-controlled.

Implementation note: The initialization vector (IV) is automatically generated
and included in the encrypted output. No need to generate it or to manage it
separately from the encrypted output.

#### `meta`

Type: `Uint8Array`

The metadata buffer to encrypt.

### `keychain.decryptMeta(ivEncryptedMeta)`
```ts
decryptMeta (ivEncryptedMeta:Uint8Array):Promise<Uint8Array>
```

Returns: `Promise<Uint8Array>`

Returns a `Promise` that resolves to a decrypted version of `encryptedMeta`.

#### `ivEncryptedMeta`

Type: `Uint8Array`

The encrypted metadata buffer to decrypt.

### `keychain.encryptBytes(bytes[, opts])`

```ts
async function encryptBytes (
    bytes:ArrayBuffer|Uint8Array,
    opts?:{ iv?:Uint8Array, size?:number },
):Promise<Uint8Array>
```

Encrypt and return the given data in-memory, not using streams. The key is
derived deterministically from the main key, so `decryptBytes` can re-derive
it and decrypt the result.

#### `opts`

Type: `{ iv?, size? }`

Optional. `size` is the derived key length in bytes (default 16); pass the
same `size` to `decryptBytes` to re-derive a matching key. `iv` is a 12-byte
initialization vector, randomly generated if omitted.

SAFETY: reusing a caller-supplied `iv` across two calls with different
plaintexts is AES-GCM nonce reuse under the same derived key, and breaks
confidentiality. Omit `iv` to get a random one per call.

### `keychain.decryptBytes(bytes[, opts])`

```ts
async function decryptBytes (
    bytes:Uint8Array,
    opts?:{ size?:number },
):Promise<ArrayBuffer>
```

Decrypt the given data in-memory, without streaming.

#### `opts`

Type: `{ size? }`

Optional. Pass the same `size` that was given to `encryptBytes`, so the
same-length key is re-derived.

### `plaintextSize(encryptedSize)`

```ts
function plaintextSize (
  encryptedSize:number,
  rs:number = RECORD_SIZE
):number
```

Given an encrypted size, return the corresponding plaintext size.

### `encryptedSize(plaintextSize)`
```ts
function encryptedSize (
  plaintextSize:number,
  rs:number = RECORD_SIZE
):number
```

Given a plaintext size, return the corresponding encrypted size.

## Reproducible & record-addressable encryption

By default, `encryptStream` uses a fresh random salt for each call.
This provides strong privacy (identical plaintexts don't leak through
repeated ciphertext), but the same input encrypted twice produces
different output.

For use cases like deduplication and content-addressed storage, you
need reproducible encryption: the same plaintext always produces
identical ciphertext. This is safe only if the salt is bound to the
plaintext, preventing a single salt from encrypting two different
contents (which would break AES-GCM).

The Keychain API enforces this binding automatically. The salt is
never chosen by the caller; it's derived from a content digest
(SHA-256 hash of the plaintext) via HKDF. This guarantees: a fixed
salt pairs with exactly one plaintext.

### Two-pass flow: hash, then encrypt

To encrypt reproducibly, first compute the content digest, then
pass it to the encrypt functions:

```js
// 1. Hash pass
const digest = await keychain.contentDigest(file.stream())

// 2. Encrypt pass — reproducible: same input -> identical ciphertext
const encrypted = await keychain.encryptStream(file.stream(), {
    contentDigest: digest,
    recordSize: rs
})

// On demand: regenerate record i byte-identically
const rec = await keychain.encryptRecord(i, sliceI, {
    isLast,
    contentDigest: digest,
    recordSize: rs
})
// Full ciphertext = header(21) || rec0 || rec1 || ... || recLast
const head = await keychain.header({
    contentDigest: digest,
    recordSize: rs
})
```

Note that `encryptStream` with no options keeps the original random-salt
behavior and is a single pass.

### Low-level ECE building blocks

The package exports low-level ECE functions at
`@vanishing.page/crypto-stream/ece`. These include `RECORD_SIZE`,
`HEADER_LENGTH`, `recordPlaintextSize`, `recordCount`, `header`,
`deriveContentSalt`, and `encryptRecord`. They take a raw salt directly
and are footgun-prone: passing the same raw salt with two different
plaintexts breaks AES-GCM (nonce-reuse catastrophe). Prefer the
Keychain API, which derives the salt from the content digest and is
nonce-reuse-safe by construction.

## credits

Thank you
[Feross](https://github.com/feross) and
[SocketDev](https://github.com/SocketDev)
team for writing and publishing the original,
[wormhole-crypto](https://github.com/SocketDev/wormhole-crypto).
