/**
 * Encryption and decryption streams for "Encrypted Content-Encoding for HTTP"
 * specification. See: https://tools.ietf.org/html/rfc8188
 */

import { concatStreams } from './concat-streams.js'
import { transformStream } from './transform-stream.js'
import { SliceTransformer } from './slice-transformer.js'
import { ExtractTransformer } from './extract-transformer.js'
import { generateSalt, asBufferSource, joinBufs } from './util.js'
import { TAG_LENGTH, KEY_LENGTH } from './constants.js'

const webcrypto = globalThis.crypto

const MODE_ENCRYPT = 'encrypt'
const MODE_DECRYPT = 'decrypt'
const NONCE_LENGTH = 12
export const RECORD_SIZE = 64 * 1024
export const HEADER_LENGTH = KEY_LENGTH + 4 + 1 // salt + record size + idlen
const MIN_RECORD_SIZE = TAG_LENGTH + 2

const encoder = new TextEncoder()
const SALT_INFO = encoder.encode('Content-Encoding: salt\0')

class ECETransformer {
    mode:'encrypt'|'decrypt'
    secretKey:CryptoKey
    rs:number|null
    salt:Uint8Array<ArrayBuffer>|null
    seekOpts:Partial<{ startSeq, endSeq, endsPrematurely }>
    seq:number
    prevChunk:Uint8Array|null
    nonceBase:Uint8Array|null
    key:CryptoKey|null

    constructor (
        mode:'encrypt'|'decrypt',
        secretKey:CryptoKey,
        rs:number|null,
        salt:Uint8Array<ArrayBuffer>|null,
        seekOpts = {}
    ) {
        if (mode !== MODE_ENCRYPT && mode !== MODE_DECRYPT) {
            throw new Error("mode must be either 'encrypt' or 'decrypt'")
        }

        checkSecretKey(secretKey)

        if (salt != null && salt.byteLength !== KEY_LENGTH) {
            throw new Error('Invalid salt length')
        }
        if (rs != null) {
            checkRecordSize(rs)
        }

        this.mode = mode
        this.secretKey = secretKey
        this.rs = rs
        this.salt = salt

        // seekOpts can contain (for decryption only):
        // startSeq: first record sequence number
        // endSeq: last record sequence number + 1 (exclusive)
        // endsPrematurely: true if the last record should have non-final padding
        this.seekOpts = seekOpts

        // sequence number. -1 is the header, 0 is the first data chunk
        this.seq = -1
        this.prevChunk = null
        this.nonceBase = null
        this.key = null
    }

    async generateKey ():Promise<CryptoKey> {
        return webcrypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: this.salt!,
                info: encoder.encode('Content-Encoding: aes128gcm\0')
            },
            this.secretKey,
            {
                name: 'AES-GCM',
                length: KEY_LENGTH * 8
            },
            false,
            ['encrypt', 'decrypt']
        )
    }

    async generateNonceBase ():Promise<Uint8Array> {
        const nonceBaseBuf = await webcrypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: this.salt!,
                info: encoder.encode('Content-Encoding: nonce\0')
            },
            this.secretKey,
            NONCE_LENGTH * 8
        )
        return new Uint8Array(nonceBaseBuf)
    }

    generateNonce (seq:number):Uint8Array<ArrayBuffer> {
        if (!Number.isSafeInteger(seq) || seq < 0) {
            throw new Error('invalid record sequence number')
        }
        if (!this.nonceBase) throw new Error('Not nonce base')

        const nonce = this.nonceBase.slice()
        let n = BigInt(seq)
        for (let i = nonce.byteLength - 1; i >= 0 && n > 0n; i -= 1) {
            nonce[i] = nonce[i] ^ Number(n & 0xffn)
            n >>= 8n
        }
        return nonce
    }

    pad (data:Uint8Array, isLast:boolean):Uint8Array<ArrayBuffer> {
        if (this.rs == null) throw new Error('Not record size')
        const len = data.byteLength
        if (len + TAG_LENGTH >= this.rs) {
            throw new Error('data too large for record size')
        }

        let padding
        if (isLast) {
            padding = Uint8Array.of(2)
        } else {
            padding = new Uint8Array(this.rs - len - TAG_LENGTH)
            padding[0] = 1
        }

        const result = new Uint8Array(data.byteLength + padding.byteLength)
        result.set(data, 0)
        result.set(padding, data.byteLength)
        return result
    }

    unpad (data:Uint8Array, isLast:boolean):Uint8Array {
        for (let i = data.byteLength - 1; i >= 0; i -= 1) {
            if (data[i] !== 0) {
                if (isLast) {
                    if (data[i] !== 2) {
                        throw new Error('delimiter of final record is not 2')
                    }
                } else {
                    if (data[i] !== 1) {
                        throw new Error('delimiter of not final record is not 1')
                    }
                }

                return data.slice(0, i)
            }
        }
        throw new Error('no delimiter found')
    }

    createHeader ():Uint8Array {
        if (!this.salt) throw new Error('Not salt')
        if (this.rs == null) throw new Error('Not record size')
        return header(this.salt, this.rs)
    }

    readHeader (
        buffer:Uint8Array
    ):{ salt:Uint8Array, rs:number, keyid:Uint8Array } {
        if (buffer.byteLength < HEADER_LENGTH) {
            throw new Error('chunk is not expected header length')
        }
        const dv = new DataView(
            buffer.buffer,
            buffer.byteOffset,
            buffer.byteLength
        )
        const idlen = dv.getUint8(KEY_LENGTH + 4)
        const expectedLength = HEADER_LENGTH + idlen
        if (buffer.byteLength !== expectedLength) {
            throw new Error('chunk is not expected header length')
        }
        const rs = dv.getUint32(KEY_LENGTH)
        checkRecordSize(rs)
        const header = {
            salt: buffer.slice(0, KEY_LENGTH),
            rs,
            keyid: buffer.slice(HEADER_LENGTH)
        }
        return header
    }

    async encryptRecord (
        record:Uint8Array,
        seq:number,
        isLast:boolean
    ):Promise<Uint8Array> {
        const nonce = this.generateNonce(seq)
        const paddedRecord = this.pad(record, isLast)

        if (!this.key) throw new Error('not key')  // for TS

        const encryptedRecordBuf = await webcrypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: TAG_LENGTH * 8
            },
            this.key,
            paddedRecord
        )

        return new Uint8Array(encryptedRecordBuf)
    }

    async decryptRecord (
        encryptedRecord:Uint8Array,
        seq:number,
        isLast:boolean
    ):Promise<Uint8Array> {
        if (!this.key) throw new Error('not key')  // for TS

        const nonce = this.generateNonce(seq)
        const paddedRecordBuf:ArrayBuffer = await webcrypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: TAG_LENGTH * 8
            },
            this.key,
            asBufferSource(encryptedRecord)
        )
        const paddedRecord = new Uint8Array(paddedRecordBuf)
        return this.unpad(paddedRecord, isLast)
    }

    async start (controller:TransformStreamDefaultController) {
        if (this.mode === MODE_ENCRYPT) {
            this.key = await this.generateKey()
            this.nonceBase = await this.generateNonceBase()
            controller.enqueue(this.createHeader())
            this.seq += 1
        }
    }

    async transformPrevChunk (
        isLast:boolean,
        controller:TransformStreamDefaultController
    ):Promise<void> {
        if (!this.prevChunk) throw new Error('not this.prevChunk')

        if (this.mode === MODE_ENCRYPT) {
            controller.enqueue(
                await this.encryptRecord(this.prevChunk, this.seq, isLast)
            )
        } else {
            if (this.seq === -1) {
                if (!this.prevChunk) throw new Error('not this.prevChunk')

                // the first chunk during decryption contains only the header
                const header = this.readHeader(this.prevChunk)
                this.salt = asBufferSource(header.salt)
                if (this.rs !== null && this.rs !== header.rs) {
                    throw new Error(
                        'Record size declared in constructor does not ' +
                        'match record size in encrypted stream'
                    )
                }
                this.rs = header.rs

                this.key = await this.generateKey()
                this.nonceBase = await this.generateNonceBase()

                const startSeq = this.seekOpts.startSeq
                if (startSeq != null && startSeq > 0) {
                    // update the sequence number if decryption doesn't start
                    // at seq = 0
                    this.seq += startSeq
                }
            } else {
                let expectEndPadding = false
                if (isLast) {
                    // verify encrypted stream length even when seeking
                    const endSeq = this.seekOpts.endSeq
                    if (endSeq != null && endSeq !== this.seq + 1) {
                        throw new Error('Incorrect encrypted stream length')
                    }

                    // if the stream ends prematurely, expect a non-end padding byte
                    expectEndPadding = !this.seekOpts.endsPrematurely
                }

                controller.enqueue(
                    await this.decryptRecord(
                        this.prevChunk,
                        this.seq,
                        expectEndPadding
                    )
                )
            }
        }

        this.seq += 1
    }

    async transform (
        chunk:Uint8Array,
        controller:TransformStreamDefaultController
    ):Promise<void> {
        if (this.prevChunk) {
            await this.transformPrevChunk(false, controller)
        }
        this.prevChunk = chunk
    }

    async flush (controller:TransformStreamDefaultController):Promise<void> {
        if (this.prevChunk) {
            await this.transformPrevChunk(true, controller)
        }
    }
}

class ECEDecryptionSlicer {
    expectedRs:number|null
    buffer:Uint8Array<ArrayBuffer>
    rs:number|null

    constructor (expectedRs?:number) {
        if (expectedRs != null) {
            checkRecordSize(expectedRs)
        }
        this.expectedRs = expectedRs ?? null
        this.buffer = new Uint8Array(0)
        this.rs = null
    }

    transform (
        chunk:Uint8Array,
        controller:TransformStreamDefaultController
    ):void {
        this.buffer = joinBufs(this.buffer, chunk)
        this.drain(controller)
    }

    flush (controller:TransformStreamDefaultController):void {
        this.drain(controller)
        if (this.rs == null) {
            throw new Error('Missing ECE header')
        }
        if (this.buffer.byteLength > 0) {
            controller.enqueue(this.buffer)
            this.buffer = new Uint8Array(0)
        }
    }

    drain (controller:TransformStreamDefaultController):void {
        if (this.rs == null) {
            if (this.buffer.byteLength < HEADER_LENGTH) return

            const dv = new DataView(
                this.buffer.buffer,
                this.buffer.byteOffset,
                this.buffer.byteLength
            )
            const idlen = dv.getUint8(KEY_LENGTH + 4)
            const headerLength = HEADER_LENGTH + idlen
            if (this.buffer.byteLength < headerLength) return

            const rs = dv.getUint32(KEY_LENGTH)
            checkRecordSize(rs)
            if (this.expectedRs != null && this.expectedRs !== rs) {
                throw new Error(
                    'Record size declared in constructor does not match ' +
                    'record size in encrypted stream'
                )
            }

            controller.enqueue(this.buffer.slice(0, headerLength))
            this.buffer = this.buffer.slice(headerLength)
            this.rs = rs
        }

        while (this.buffer.byteLength >= this.rs) {
            controller.enqueue(this.buffer.slice(0, this.rs))
            this.buffer = this.buffer.slice(this.rs)
        }
    }
}

/**
 * Given a plaintext size, return the corresponding encrypted size.
 *
 * plaintextSize: int containing plaintext size
 * rs:            int containing record size, optional
 */
export function encryptedSize (
    plaintextSize:number,
    rs:number = RECORD_SIZE
):number {
    if (!Number.isInteger(plaintextSize)) {
        throw new TypeError('plaintextSize')
    }
    checkRecordSize(rs)

    const chunkMetaLength = TAG_LENGTH + 1   // Chunk metadata, tag and delimiter
    return (
        HEADER_LENGTH +
        plaintextSize +
        chunkMetaLength * Math.ceil(plaintextSize / (rs - chunkMetaLength))
    )
}

/**
 * Given an encrypted size, return the corresponding plaintext size.
 *
 * encryptedSize: int containing encrypted size
 * rs:            int containing record size, optional
 */
export function plaintextSize (
    encryptedSize:number,
    rs:number = RECORD_SIZE
):number {
    if (!Number.isInteger(encryptedSize)) {
        throw new TypeError('encryptedSize')
    }
    checkRecordSize(rs)
    if (encryptedSize < HEADER_LENGTH) {
        throw new RangeError(
            `encryptedSize must be at least ${HEADER_LENGTH} (HEADER_LENGTH)`
        )
    }

    const chunkMetaLength = TAG_LENGTH + 1   // Chunk metadata, tag and delimiter
    const encryptedRecordsSize = encryptedSize - HEADER_LENGTH
    return (
        encryptedRecordsSize -
        chunkMetaLength *
        Math.ceil(encryptedRecordsSize / rs)
    )
}

/**
 * Plaintext bytes that fit in one ECE record for the given record size.
 * Equals `rs - TAG_LENGTH - 1` (the 16-byte AES-GCM tag plus the 1-byte
 * padding delimiter).
 *
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns Plaintext bytes per record.
 */
export function recordPlaintextSize (rs:number = RECORD_SIZE):number {
    checkRecordSize(rs)
    return rs - TAG_LENGTH - 1
}

/**
 * Number of ECE data records needed to hold `plaintextSize` bytes. Returns 0
 * for empty input — an empty stream encrypts to a header with no
 * data records.
 *
 * @param plaintextSize Total plaintext length in bytes.
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns Record count (0 when plaintextSize is 0).
 */
export function recordCount (
    plaintextSize:number,
    rs:number = RECORD_SIZE
):number {
    if (!Number.isInteger(plaintextSize)) {
        throw new TypeError('plaintextSize')
    }
    checkRecordSize(rs)
    return Math.ceil(plaintextSize / recordPlaintextSize(rs))
}

/**
 * Build the canonical 21-byte ECE header:
 * `salt(16) || recordSize(uint32 BE) || idlen(0)`.
 *
 * This is the single source of truth for the header; the streaming encoder
 * delegates to it, so a standalone header is byte-identical to the stream's
 * header.
 *
 * SAFETY: a fixed salt must never encrypt two different plaintexts under the
 * same key (AES-GCM nonce reuse). Prefer deriving the salt from the content
 * (see `deriveContentSalt`) over choosing it directly. This is a low-level
 * building block; the Keychain API does not accept a raw salt.
 *
 * @param salt 16-byte content salt.
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns The 21-byte header.
 */
export function header (
    salt:Uint8Array<ArrayBuffer>,
    rs:number = RECORD_SIZE
):Uint8Array<ArrayBuffer> {
    if (salt.byteLength !== KEY_LENGTH) {
        throw new Error('Invalid salt length')
    }
    checkRecordSize(rs)
    const buf = new Uint8Array(HEADER_LENGTH)
    buf.set(salt)
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
    dv.setUint32(KEY_LENGTH, rs)
    return buf
}

/**
 * Derive a deterministic 16-byte content salt from the secret key and a
 * content digest, via HKDF-SHA256 with info
 * `"Content-Encoding: salt\0" || contentDigest`.
 *
 * Because the digest is collision-resistant over the plaintext, a salt is
 * cryptographically bound to exactly one content — so a fixed salt can never
 * pair with two different plaintexts. This is what makes reproducible
 * encryption safe under AES-GCM (no nonce reuse across distinct plaintexts).
 *
 * @param secretKey HKDF CryptoKey (the main secret key).
 * @param contentDigest Digest of the plaintext (e.g. 32-byte SHA-256).
 * @returns 16-byte content salt.
 */
export async function deriveContentSalt (
    secretKey:CryptoKey,
    contentDigest:Uint8Array
):Promise<Uint8Array<ArrayBuffer>> {
    if (contentDigest.byteLength === 0) {
        throw new Error('empty content digest')
    }

    const infoLen = SALT_INFO.byteLength + contentDigest.byteLength
    const info = new Uint8Array(infoLen)
    info.set(SALT_INFO, 0)
    info.set(contentDigest, SALT_INFO.byteLength)

    const bits = await webcrypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info
        },
        secretKey,
        KEY_LENGTH * 8
    )

    return new Uint8Array(bits)
}

/**
 * Encrypt a single ECE record in isolation, byte-identical to record `seq` of
 * the corresponding `encryptStream` output. Drives an `ECETransformer` through
 * its existing key/nonce/record methods, so no new crypto is introduced.
 *
 * Non-final records must be exactly `recordPlaintextSize(rs)` bytes; the final
 * record must be `<= recordPlaintextSize(rs)` bytes.
 *
 * SAFETY: the same `(secretKey, salt)` must never encrypt two different
 * plaintexts (AES-GCM nonce reuse). This low-level function takes a raw salt;
 * derive it from the content via `deriveContentSalt`, or use the Keychain API,
 * which never exposes a raw salt.
 *
 * @param secretKey HKDF CryptoKey (the main secret key).
 * @param seq Zero-based record index.
 * @param plaintext The record's plaintext slice.
 * @param isLast Whether this is the final record.
 * @param salt 16-byte content salt (same salt as the stream's header).
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns The encrypted record bytes.
 */
export async function encryptRecord (
    secretKey:CryptoKey,
    seq:number,
    plaintext:Uint8Array,
    isLast:boolean,
    salt:Uint8Array<ArrayBuffer>,
    rs:number = RECORD_SIZE
):Promise<Uint8Array> {
    // Validates the key and the salt length (throws 'Invalid salt length').
    const transformer = new ECETransformer(MODE_ENCRYPT, secretKey, rs, salt)

    const max = recordPlaintextSize(rs)
    if (isLast) {
        if (plaintext.byteLength > max) {
            throw new Error('final record exceeds recordPlaintextSize')
        }
    } else {
        if (plaintext.byteLength !== max) {
            throw new Error('non-final record must equal recordPlaintextSize')
        }
    }

    transformer.key = await transformer.generateKey()
    transformer.nonceBase = await transformer.generateNonceBase()

    return transformer.encryptRecord(plaintext, seq, isLast)
}

/**
 * Given a plaintext stream `input`, return an encrypted stream.
 *
 * input:     a ReadableStream containing data to be transformed
 * secretKey: CryptoKey containing secret key of size KEY_LENGTH
 * rs:        int containing record size, optional
 * salt:      Uint8Array containing salt of KEY_LENGTH length, optional
 */
export function encryptStream (
    input:ReadableStream,
    secretKey:CryptoKey,
    rs:number = RECORD_SIZE,
    salt:Uint8Array<ArrayBuffer> = generateSalt(KEY_LENGTH)
):ReadableStream {
    const stream = transformStream(
        input,
        new SliceTransformer(rs - TAG_LENGTH - 1)
    ).readable

    return transformStream(
        stream,
        new ECETransformer(MODE_ENCRYPT, secretKey, rs, salt)
    ).readable
}

/**
 * Given an encrypted stream `input`, return a plaintext stream.
 *
 * input:     a ReadableStream containing data to be transformed
 * secretKey: CryptoKey containing secret key of size KEY_LENGTH
 * rs:        int containing record size, optional
 */
export function decryptStream (
    input:ReadableStream,
    secretKey:CryptoKey,
    rs?:number
):ReadableStream {
    const stream = transformStream(
        input,
        new ECEDecryptionSlicer(rs)
    ).readable

    return transformStream(
        stream,
        new ECETransformer(MODE_DECRYPT, secretKey, rs ?? null, null)
    ).readable
}

/**
 * Given a desired plaintext byte range specified by `offset` and `length`,
 * and the total size of the encrypted stream in `totalEncryptedLength`,
 * provides a mechanism to decrypt that range.
 *
 * To decrypt an arbitrary plaintext range, the client will need to supply
 * multiple (currently always two) ranges of encrypted data.
 * `decryptStreamRange` returns a promise that resolves to an object containing
 * `ranges`, which is an array of { offset, length } entries specifying the
 * needed encrypted byte ranges, and `encrypt`, a callback function.
 *
 * Once the client has gathered an array `streams` of encrypted ReadableStreams,
 * one for each of these ranges, it should call `decrypt(streams)`. This will
 * then return the final plaintext ReadableStream.
 *
 * secretKey:             CryptoKey containing secret key of size KEY_LENGTH
 * offset:                int containing plaintext byte offset at which to start decryption
 * length:                int containing the number of plaintext bytes to decrypt
 * totalEncryptedLength:  The total number of bytes in the encrypted stream
 * rs:                    int containing record size, optional
 */
export function decryptStreamRange (
    secretKey:CryptoKey,
    offset:number,
    length:number,
    totalEncryptedLength:number,
    rs:number = RECORD_SIZE
):{
    ranges:{ offset:number, length:number }[],
    decrypt:(streams:ReadableStream[])=>ReadableStream
} {
    checkRecordSize(rs)

    // Chunk metadata, tag and delimiter
    const chunkMetaLength = TAG_LENGTH + 1

    // First record needed to decrypt the range
    const startRecord = Math.floor(offset / (rs - chunkMetaLength))
    const offsetInStartRecord = offset % (rs - chunkMetaLength)

    // Record after the last record needed to decrypt the range
    const endRecord = Math.ceil((offset + length) / (rs - chunkMetaLength))

    // Range needed for data (not header) stream
    const dataOffset = HEADER_LENGTH + startRecord * rs
    let dataEnd = HEADER_LENGTH + endRecord * rs // exclusive

    // Determine if the stream ends at the end of the encrypted file.
    // This is necessary to correctly validate the padding of the final record.
    const endsPrematurely = dataEnd < totalEncryptedLength
    if (!endsPrematurely) {
        dataEnd = totalEncryptedLength
    }

    return {
        ranges: [
            {
                offset: 0,
                length: HEADER_LENGTH
            }, {
                offset: dataOffset,
                length: dataEnd - dataOffset
            }
        ],

        decrypt: (streams) => {
            if (!(streams.every(stream => stream instanceof ReadableStream))) {
                throw new TypeError('Stream is not a ReadableStream')
            }

            // Combine the header and data streams, and then slice how
            // ECETransformer expects
            const encryptedStream = transformStream(
                concatStreams(streams), new SliceTransformer(HEADER_LENGTH, rs)
            ).readable

            // Plaintext stream of needed records
            const plaintextStream = transformStream(
                encryptedStream,
                new ECETransformer(MODE_DECRYPT, secretKey, rs, null, {
                    startSeq: startRecord,
                    endSeq: endRecord,
                    endsPrematurely
                })
            ).readable

            // Extract the exact needed bytes from the plaintext stream
            return transformStream(
                plaintextStream,
                new ExtractTransformer(offsetInStartRecord, length)
            ).readable
        }
    }
}

function checkSecretKey (secretKey:CryptoKey):void {
    if (secretKey.type !== 'secret') {
        throw new Error('Invalid key: type must be "secret"')
    }
    if (secretKey.algorithm.name !== 'HKDF') {
        throw new Error('Invalid key: algorithm must be HKDF')
    }
    if (!secretKey.usages.includes('deriveKey')) {
        throw new Error('Invalid key: usages must include deriveKey')
    }
    if (!secretKey.usages.includes('deriveBits')) {
        throw new Error('Invalid key: usages must include deriveBits')
    }
}

function checkRecordSize (rs:number):void {
    if (!Number.isInteger(rs)) {
        throw new TypeError('rs')
    }
    if (rs < MIN_RECORD_SIZE) {
        throw new RangeError('rs must be at least 18')
    }
    if (rs > 0xffffffff) {
        throw new RangeError('rs must fit uint32')
    }
}
