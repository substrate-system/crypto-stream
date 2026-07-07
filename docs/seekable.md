# Proposal: deterministic + record-addressable encryption

> Historical design note. This document describes the older raw-salt
> proposal that led to the current API. The implemented `Keychain` API no
> longer accepts raw content salts; it derives the ECE stream salt from
> `contentDigest` and writes that salt into the RFC 8188 content-coding
> header. Treat `README.md` and `src/keychain.ts` as the current API.

Target repo: `@substrate-system/crypto-stream` (verified against the
installed `0.0.35` dist).

This is a paste-ready spec for two small, related additions to the
`Keychain` / ECE layer. They let a consumer (vanishing.page's p2p file
transfer) regenerate any single ciphertext record on demand, so a large
file can be seeded over WebRTC without buffering the whole ciphertext.

Both additions are backward compatible (opt-in) and reuse machinery the
library already has.

---

## Background: what already exists

`crypto-stream` is an RFC 8188 (Encrypted Content-Encoding) scheme. From
`dist/src/ece.js`:

- `RECORD_SIZE = 64 * 1024`, `TAG_LENGTH = 16`, `KEY_LENGTH = 16`.
- `HEADER_LENGTH = KEY_LENGTH + 4 + 1 = 21` bytes: `salt(16) ||
  recordSize(4) || idlen(1)`.
- Plaintext is sliced into records of `rs - TAG_LENGTH - 1` (`= rs - 17`)
  bytes via `SliceTransformer(rs - TAG_LENGTH - 1)`.
- The content key is `HKDF(mainKey, salt, "Content-Encoding:
  aes128gcm\0")`; the nonce base is `HKDF(mainKey, salt,
  "Content-Encoding: nonce\0")`; and the per-record nonce is
  `nonceBase` with its last 4 bytes XOR'd with the record sequence
  number (`ECETransformer.generateNonce`). The header is sequence `-1`;
  data records are `0, 1, 2, ...`.
- Padding is deterministic: a non-final record is padded to `rs - TAG`
  with a leading `0x01` byte; the final record gets a single `0x02`
  delimiter (`ECETransformer.pad`).

**Consequence:** given a fixed `(mainKey, salt, recordSize)`, the bytes
of record `seq` are a pure function of `seq`, the record's plaintext
slice, and whether it is the final record. Encryption is already
deterministic *internally* — the tree just isn't exposed.

The library already ships the **read-side** seek primitive:
`decryptStreamRange(secretKey, offset, length, totalEncryptedLength,
rs)` (and `Keychain.decryptStreamRange`) computes which encrypted byte
ranges cover a requested plaintext range and decrypts records
`startRecord..endRecord` using `seekOpts { startSeq, endSeq,
endsPrematurely }`. The write-side has no equivalent.

---

## Gap 1: `Keychain.encryptStream` is not reproducible

`Keychain.encryptStream` (`dist/src/keychain.js`) calls the ECE
`encryptStream(stream, mainKey)` with **no salt argument**, so ECE falls
back to `generateSalt(KEY_LENGTH)` — a *fresh random salt per call*,
embedded in the 21-byte header. The keychain's own fixed `this.salt`
(used for the metadata key and auth token) is never threaded into the
content encryption.

So two `encryptStream` calls over identical input produce **different**
ciphertext, and the Bao root over that ciphertext is unstable. For a
content-addressed transfer (the root must be computed once, then any
chunk regenerated to match) this is a blocker.

### Proposed change (opt-in, backward compatible)

```ts
interface EncryptOpts {
    // Fix the content salt so output is byte-for-byte reproducible.
    // Defaults to a fresh random salt (current behavior) when omitted.
    salt?:Uint8Array;       // must be KEY_LENGTH (16) bytes
    recordSize?:number;     // defaults to RECORD_SIZE (65536)
}

class Keychain {
    encryptStream (
        stream:ReadableStream<Uint8Array>,
        opts?:EncryptOpts
    ):Promise<ReadableStream<Uint8Array>>
}
```

Implementation is a one-liner over the existing ECE function:

```js
async encryptStream (stream, opts = {}) {
    if (!(stream instanceof ReadableStream)) {
        throw new TypeError('This is not a readable stream')
    }
    const mainKey = await this.mainKeyPromise
    // ece.encryptStream(input, secretKey, rs?, salt?)
    return encryptStream(stream, mainKey, opts.recordSize, opts.salt)
}
```

Passing `opts.salt = this.salt` is safe: the content key, nonce base,
metadata key, and auth token are all HKDF outputs with **different
`info` strings**, so they stay independent even when they share a salt.

---

## Gap 2: no record-addressable (single-record) encryption

To seed a large file without buffering, a consumer needs to produce the
exact bytes of ciphertext record `seq` on demand, given only that
record's plaintext slice (which it reads lazily from a `File`/`Blob`).
`ECETransformer.encryptRecord(record, seq, isLast)` already does exactly
this — it's just private.

### Proposed API

Expose the record geometry and a single-record encrypt, symmetric to the
existing `decryptStreamRange`.

New exports from `ece.js`:

```ts
export const RECORD_SIZE:number;       // 65536
export const HEADER_LENGTH:number;     // 21

// plaintext bytes carried by one record
export function recordPlaintextSize (rs?:number):number;   // rs - 17

// number of data records for a plaintext of `len` bytes
export function recordCount (plaintextSize:number, rs?:number):number;

// the 21-byte ECE header for a salt + record size
export function header (salt:Uint8Array, rs?:number):Uint8Array;

// Deterministically encrypt ONE record. Byte-identical to the record
// the streaming encryptStream() emits at sequence `seq` for the same
// (secretKey, salt, rs).
//   seq:       0-based data-record index
//   plaintext: this record's plaintext slice; length must equal
//              recordPlaintextSize(rs) for non-final records, and be
//              <= recordPlaintextSize(rs) for the final record
//   isLast:    final record? (delimiter 0x02 vs 0x01)
export function encryptRecord (
    secretKey:CryptoKey,
    seq:number,
    plaintext:Uint8Array,
    isLast:boolean,
    salt:Uint8Array,
    rs?:number
):Promise<Uint8Array>;
```

New `Keychain` methods (the public surface consumers should use):

```ts
class Keychain {
    // Reproducible 21-byte header (the chunk-0 prefix). Defaults salt
    // to this.salt.
    header (opts?:{ salt?:Uint8Array; recordSize?:number }):Uint8Array;

    // Regenerate the exact ciphertext bytes for record `seq`.
    encryptRecord (
        seq:number,
        plaintext:Uint8Array,
        opts:{ isLast:boolean; salt?:Uint8Array; recordSize?:number }
    ):Promise<Uint8Array>;
}
```

### Reference implementation

In `ece.js` — reuse the existing `ECETransformer` private methods rather
than duplicating the crypto:

```js
export const RECORD_SIZE = 64 * 1024
// HEADER_LENGTH already computed internally; just export it.

export function recordPlaintextSize (rs = RECORD_SIZE) {
    return rs - TAG_LENGTH - 1
}

export function recordCount (plaintextSize, rs = RECORD_SIZE) {
    return Math.max(1, Math.ceil(plaintextSize / recordPlaintextSize(rs)))
}

export function header (salt, rs = RECORD_SIZE) {
    if (salt.byteLength !== KEY_LENGTH) throw new Error('Invalid salt length')
    const h = new Uint8Array(HEADER_LENGTH)
    h.set(salt)
    new DataView(h.buffer).setUint32(KEY_LENGTH, rs)
    return h
}

export async function encryptRecord (
    secretKey, seq, plaintext, isLast, salt, rs = RECORD_SIZE
) {
    const t = new ECETransformer(MODE_ENCRYPT, secretKey, rs, salt)
    t.key = await t.generateKey()           // existing private method
    t.nonceBase = await t.generateNonceBase()  // existing private method
    return t.encryptRecord(plaintext, seq, isLast)  // existing private method
}
```

In `keychain.js`:

```js
header (opts = {}) {
    return eceHeader(opts.salt ?? this.salt, opts.recordSize)
}

async encryptRecord (seq, plaintext, opts) {
    const mainKey = await this.mainKeyPromise
    return eceEncryptRecord(
        mainKey, seq, plaintext, !!opts.isLast,
        opts.salt ?? this.salt, opts.recordSize
    )
}
```

(`generateKey` / `generateNonceBase` / `encryptRecord` already exist on
`ECETransformer`; no new crypto is introduced.)

---

## How the consumer composes these (context, not a requirement)

The full ciphertext is `header(21) || rec0 || rec1 || ... || recLast`.
The seeder:

1. Picks a deterministic salt (the message `Keychain`'s `this.salt`) and
   a record size `rs` (the consumer's `P2P_CHUNK_SIZE`, set equal to one
   record so chunk boundaries line up).
2. Computes the Bao root once over a streamed `encryptStream(file.stream(),
   { salt, recordSize: rs })` pass (no buffering).
3. On a peer's request for chunk `i`, reads plaintext bytes
   `[i * recordPlaintextSize(rs), ...]` from the `File` and calls
   `encryptRecord(i, slice, { isLast: i === recordCount - 1, salt,
   recordSize: rs })`.

Because the header is a fixed 21-byte prefix that does not align to a
record boundary, exposing `header()` and `recordPlaintextSize()` lets the
consumer keep the header out of the chunk grid (prepend it locally before
`decryptStream`) so each Bao chunk maps to exactly one encrypted record.

---

## Tests to add

- **Determinism:** `encryptStream(x, { salt })` twice → identical bytes.
- **Record equivalence:** sequential `encryptStream(x, { salt, recordSize })`
  collected to a buffer equals `header(salt, rs) || concat(encryptRecord(i,
  slice_i, { isLast }) for i in 0..recordCount-1)`, byte for byte.
- **Round-trip:** `decryptStream` of the per-record concatenation recovers
  the plaintext.
- **Last-record padding:** a plaintext whose length is an exact multiple
  of `recordPlaintextSize(rs)` still produces a valid final record.
- **Backward compat:** `encryptStream(x)` with no opts still uses a random
  salt and still round-trips.

---

## Why not just use `decryptStreamRange` shape on the write side?

`decryptStreamRange` is range-of-bytes oriented (it needs the header +
two encrypted ranges and re-slices). For seeding we want the inverse and
simpler unit: "give me record `i`." A single-record encrypt is the
minimal primitive, maps 1:1 to a Bao/p2p chunk, and has no cross-record
state. The range API stays as-is for reads.

```
/ed3d-plan-and-execute:execute-implementation-plan /Users/nick/code/crypto-stream/docs/implementation-plans/2026-06-19-seekable-write/ /Users/nick/code/crypto-stream/
```
