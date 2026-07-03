import { webcrypto } from '@substrate-system/one-webcrypto'
import * as u from 'uint8arrays'
import {
    decryptStream,
    decryptStreamRange,
    deriveContentSalt,
    encryptStream,
    header as eceHeader,
    encryptRecord as eceEncryptRecord,
    KEY_LENGTH,
    RECORD_SIZE,
} from './ece.js'
import { randomBuf, joinBufs, asBufferSource } from './util.js'

export { encryptedSize, plaintextSize } from './ece.js'

const IV_LENGTH = 12
const encoder = new TextEncoder()

export class Keychain {
    key:Uint8Array<ArrayBuffer>
    salt:Uint8Array<ArrayBuffer>
    mainKeyPromise:Promise<CryptoKey>
    metaKeyPromise:Promise<CryptoKey>
    authTokenPromise:Promise<Uint8Array>

    constructor (key?:string|Uint8Array, salt?:string|Uint8Array) {
        this.key = decodeBits(key)
        this.salt = decodeBits(salt)

        this.mainKeyPromise = webcrypto.subtle.importKey(
            'raw',
            this.key,
            'HKDF',
            false,
            ['deriveBits', 'deriveKey']
        )

        this.metaKeyPromise = this.mainKeyPromise
            .then(mainKey =>
                webcrypto.subtle.deriveKey(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: this.salt,
                        info: encoder.encode('metadata')
                    },
                    mainKey,
                    {
                        name: 'AES-GCM',
                        length: 128
                    },
                    false,
                    ['encrypt', 'decrypt']
                )
            )

        this.authTokenPromise = this.mainKeyPromise
            .then(mainKey =>
                webcrypto.subtle.deriveBits(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: this.salt,
                        info: encoder.encode('authentication')
                    },
                    mainKey,
                    128
                )
            )
            .then(authTokenBuf => new Uint8Array(authTokenBuf))
    }

    /**
     * Get an authentication header as a static method.
     */
    static async AuthHeader (secretKey:string, salt:string|Uint8Array) {
        const key = decodeBits(secretKey)
        const mainKey = await webcrypto.subtle.importKey(
            'raw',
            key,
            'HKDF',
            false,
            ['deriveBits', 'deriveKey']
        )

        const token = await webcrypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: decodeBits(salt),
                info: encoder.encode('authentication')
            },
            mainKey,
            128
        )

        return Keychain.Header(arrayToB64(new Uint8Array(token)))
    }

    static Header (writeToken:string) {
        return `Bearer sync-v1 ${writeToken}`
    }

    /**
     * Get the main key as a `base64url` encoded string
     */
    get keyB64 ():string {
        return arrayToB64Url(this.key)
    }

    /**
     * Get the salt as base64 string
     */
    get saltB64 ():string {
        return arrayToB64(this.salt)
    }

    /**
     * get a promise for the auth token.
     * @returns {Promise<Uint8Array>}
     */
    async authToken ():Promise<Uint8Array> {
        return await this.authTokenPromise
    }

    /**
     * Get the auth token as a base64 string
     */
    async authTokenB64 ():Promise<string> {
        const authToken = await this.authToken()
        return arrayToB64(authToken)
    }

    /**
     * Get a header string: `Bearer sync-v1 ${authTokenB64}`.
     * Pass in a token, or else this will use the `authToken` derived from
     * the main key.
     */
    async authHeader (tokenString?:string):Promise<string> {
        if (tokenString) {
            return `Bearer sync-v1 ${tokenString}`
        }
        const authTokenB64 = await this.authTokenB64()
        return `Bearer sync-v1 ${authTokenB64}`
    }

    /**
     * Set the auth token
     * @param authToken The new token
     */
    setAuthToken (authToken?:string|Uint8Array):void {
        this.authTokenPromise = Promise.resolve(decodeBits(authToken))
    }

    /**
     * SHA-256 digest of the plaintext, used as the input to content-bound
     * salt derivation. Accepts a stream, a byte array, or a Blob;
     * equivalent content yields the same digest.
     *
     * Pass the result to `encryptStream`/`header`/`encryptRecord` as
     * `contentDigest`. The salt is derived from this digest internally,
     * so the Keychain API never exposes a raw salt — a fixed salt can
     * never pair with two different plaintexts.
     *
     * NOTE: WebCrypto has no incremental hash, so a stream/Blob is
     * drained into memory before hashing.
     *
     * @param content Plaintext as a ReadableStream, Uint8Array, or Blob.
     * @returns 32-byte SHA-256 digest.
     */
    async contentDigest (
        content:ReadableStream<Uint8Array>|Uint8Array|Blob
    ):Promise<Uint8Array<ArrayBuffer>> {
        let bytes:Uint8Array
        if (content instanceof Uint8Array) {
            bytes = content
        } else if (content instanceof ReadableStream) {
            bytes = new Uint8Array(await new Response(content).arrayBuffer())
        } else if (typeof Blob !== 'undefined' && content instanceof Blob) {
            bytes = new Uint8Array(await content.arrayBuffer())
        } else {
            throw new TypeError(
                'content must be a ReadableStream, Uint8Array, or Blob'
            )
        }

        const digest = await webcrypto.subtle.digest(
            'SHA-256',
            asBufferSource(bytes)
        )
        return new Uint8Array(digest)
    }

    /**
     * Take a stream, return an encrypted stream.
     *
     * With `opts.contentDigest`, the ECE salt is derived from the digest
     * internally (`deriveContentSalt`), so two calls over identical input
     * produce byte-identical ciphertext (reproducible encryption). With no
     * opts, a fresh random salt is used (today's behavior).
     *
     * The salt is never accepted directly: because it is bound to the
     * content digest, a fixed salt can never encrypt two different
     * plaintexts (AES-GCM nonce-reuse is structurally unreachable from
     * this API).
     *
     * @param stream Input plaintext stream.
     * @param opts Optional `{ contentDigest?, recordSize? }`.
     * @returns Encrypted stream.
     */
    async encryptStream (
        stream:ReadableStream<Uint8Array>,
        opts?:{
            contentDigest?:Uint8Array,
            recordSize?:number
        }
    ):Promise<ReadableStream<Uint8Array>> {
        if (!(stream instanceof ReadableStream)) {
            throw new TypeError('This is not a readable stream')
        }
        const mainKey = await this.mainKeyPromise
        const rs = opts?.recordSize ?? RECORD_SIZE

        if (opts?.contentDigest) {
            const salt = await deriveContentSalt(mainKey, opts.contentDigest)
            return encryptStream(stream, mainKey, rs, salt)
        }

        return encryptStream(stream, mainKey, rs)
    }

    /**
     * Build the 21-byte ECE header for content identified by
     * `contentDigest`. The salt is derived internally from the digest,
     * so this never exposes a raw salt. The header is byte-identical to
     * the header that `encryptStream({ contentDigest, recordSize })`
     * emits for the same input.
     *
     * @param opts `{ contentDigest, recordSize? }`.
     * @returns The 21-byte header.
     */
    async header (
        opts:{contentDigest:Uint8Array, recordSize?:number}
    ):Promise<Uint8Array<ArrayBuffer>> {
        const mainKey = await this.mainKeyPromise
        const salt = await deriveContentSalt(mainKey, opts.contentDigest)
        return eceHeader(salt, opts.recordSize ?? RECORD_SIZE)
    }

    /**
     * Encrypt a single ECE record by index, byte-identical to record
     * `seq` of `encryptStream({ contentDigest, recordSize })`. The salt
     * is derived from `contentDigest` internally; no raw salt is
     * accepted.
     *
     * Non-final records must be exactly `recordPlaintextSize(recordSize)`
     * bytes; the final record must be `<=` that. The low-level function
     * throws otherwise.
     *
     * @param seq Zero-based record index.
     * @param plaintext The record's plaintext slice.
     * @param opts `{ isLast, contentDigest, recordSize? }`.
     * @returns The encrypted record bytes.
     */
    async encryptRecord (
        seq:number,
        plaintext:Uint8Array,
        opts:{
            isLast:boolean,
            contentDigest:Uint8Array,
            recordSize?:number
        }
    ):Promise<Uint8Array> {
        const mainKey = await this.mainKeyPromise
        const salt = await deriveContentSalt(
            mainKey,
            opts.contentDigest
        )
        return eceEncryptRecord(
            mainKey,
            seq,
            plaintext,
            opts.isLast,
            salt,
            opts.recordSize ?? RECORD_SIZE
        )
    }

    /**
     * Encrypt and return some data; don't stream.
     *
     * NOTE: The key is derived deterministically from the main key via
     * `this.generateKey`, not freshly generated — that is why
     * `decryptBytes` is able to re-derive the same key and decrypt.
     *
     * SAFETY: if a caller-supplied `iv` is reused across two calls with
     * different plaintexts (same derived key), that is AES-GCM nonce
     * reuse and breaks confidentiality. Omit `iv` to get a random one
     * per call.
     *
     * @param bytes
     * @param {{ iv?:Uint8Array, size?:number }} [opts] Optional params,
     * `iv` and `size`. If `size` is omitted, default is 16 bytes. `iv` is
     * a random 12 bytes, will be generated if not passed in.
     * @returns {Promise<Uint8Array>}
     */
    async encryptBytes (
        bytes:ArrayBuffer|Uint8Array,
        opts?:{ iv?:Uint8Array, size?:number },
    ):Promise<Uint8Array> {
        const iv = opts?.iv || randomBuf(12)
        const encryptedRecordBuf = await webcrypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: asBufferSource(iv),
            },
            await this.generateKey(opts?.size),
            asBufferSource(bytes)
        )

        return joinBufs(iv, encryptedRecordBuf)
    }

    /**
     * Decrypt in memory, not streaming.
     *
     * @param bytes
     * @param {{ size?:number }} [opts] Pass the same `size` that was
     * given to `encryptBytes`, so the same-length key is re-derived.
     * @returns {Promise<ArrayBuffer>}
     */
    async decryptBytes (
        bytes:Uint8Array,
        opts?:{ size?:number },
    ):Promise<ArrayBuffer> {
        const key = await this.generateKey(opts?.size)
        // `iv` is prepended to the encrypted text
        const iv = bytes.slice(0, 12)
        const cipherBytes = bytes.slice(12)
        const msgBuf = await webcrypto.subtle.decrypt({
            name: 'AES-GCM',
            iv
        }, key, cipherBytes)

        return msgBuf
    }

    /**
     * Derive a new AES-GCM key from the main key.
     *
     * @param {number} [keyLength] Optional size for the key, in bytes, eg,
     * `16` or `32`.
     * @returns {Promise<CryptoKey>}
     */
    async generateKey (keyLength?:number):Promise<CryptoKey> {
        const keySize = (keyLength || KEY_LENGTH) * 8

        return webcrypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: this.salt!,
                info: encoder.encode('Content-Encoding: aes128gcm\0')
            },
            (await this.mainKeyPromise),
            {
                name: 'AES-GCM',
                length: keySize
            },
            false,
            ['encrypt', 'decrypt']
        )
    }

    /**
     * Take an encrypted stream, return a decrypted stream.
     * @param encryptedStream The input (encrypted) stream
     * @param opts `{ recordSize? }`. Pass the same `recordSize` that was
     * used to encrypt the stream; defaults to `RECORD_SIZE` (65536).
     * @returns The decrypted stream
     */
    async decryptStream (
        encryptedStream:ReadableStream<Uint8Array>,
        opts?:{ recordSize?:number }
    ):Promise<ReadableStream<Uint8Array>> {
        if (!(encryptedStream instanceof ReadableStream)) {
            throw new TypeError('encryptedStream is not a ReadableStream')
        }
        const mainKey = await this.mainKeyPromise
        return decryptStream(
            encryptedStream,
            mainKey,
            opts?.recordSize ?? RECORD_SIZE
        )
    }

    /**
     * Returns an object containing `ranges`, an array of objects
     * containing `offset` and `length` integers specifying the encrypted byte
     * ranges that are needed to decrypt the client's specified range, and a
     * `decrypt` function.
     *
     * @param {number} offset Integer
     * @param {number} length Integer
     * @param {number} totalEncryptedLength Integer
     * @param {{ recordSize?:number }} [opts] Pass the same `recordSize`
     * that was used to encrypt the stream; defaults to `RECORD_SIZE`
     * (65536).
     * @returns {Promise<{ ranges, decrypt }>}
     */
    async decryptStreamRange (
        offset:number,
        length:number,
        totalEncryptedLength:number,
        opts?:{ recordSize?:number }
    ):Promise<{
        ranges:{ offset:number, length:number }[],
        decrypt:(streams:ReadableStream[])=>ReadableStream
    }> {
        if (!Number.isInteger(offset)) {
            throw new TypeError('offset')
        }
        if (!Number.isInteger(length)) {
            throw new TypeError('length')
        }
        if (!Number.isInteger(totalEncryptedLength)) {
            throw new TypeError('totalEncryptedLength')
        }

        const mainKey = await this.mainKeyPromise
        return decryptStreamRange(
            mainKey,
            offset,
            length,
            totalEncryptedLength,
            opts?.recordSize ?? RECORD_SIZE
        )
    }

    async encryptMeta (meta:Uint8Array):Promise<Uint8Array> {
        if (!(meta instanceof Uint8Array)) {
            throw new TypeError('`meta` should be Uint8Array')
        }

        const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH))
        const metaKey:CryptoKey = await this.metaKeyPromise

        const encryptedMetaBuf:ArrayBuffer = await webcrypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
                tagLength: 128
            },
            metaKey,
            asBufferSource(meta)
        )

        const encryptedMeta = new Uint8Array(encryptedMetaBuf)

        const ivEncryptedMeta = new Uint8Array(IV_LENGTH + encryptedMeta.byteLength)
        ivEncryptedMeta.set(iv, 0)
        ivEncryptedMeta.set(encryptedMeta, IV_LENGTH)

        return ivEncryptedMeta
    }

    async decryptMeta (ivEncryptedMeta:Uint8Array):Promise<Uint8Array> {
        if (!(ivEncryptedMeta instanceof Uint8Array)) {
            throw new Error('ivEncryptedMeta')
        }

        const iv = ivEncryptedMeta.slice(0, IV_LENGTH)
        const encryptedMeta = ivEncryptedMeta.slice(IV_LENGTH)

        const metaKey = await this.metaKeyPromise
        const metaBuf = await webcrypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv,
                tagLength: 128
            },
            metaKey,
            encryptedMeta
        )
        const meta = new Uint8Array(metaBuf)
        return meta
    }
}

function arrayToB64 (array:Uint8Array):string {
    return u.toString(array, 'base64pad')
}

/**
 * Return the given Uint8Array as a base64url string.
 * @param array Uint8Array
 * @returns `base64url` encoded string
 */
function arrayToB64Url (array:Uint8Array):string {
    return u.toString(array, 'base64url')
}

function b64ToArray (str:string):Uint8Array<ArrayBuffer> {
    // Accept both base64 and base64url input by normalizing url-safe chars.
    return u.fromString(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}

function decodeBits (
    bitsB64?:Uint8Array|string|null
):Uint8Array<ArrayBuffer> {
    let result
    if (bitsB64 instanceof Uint8Array) {
        result = asBufferSource(bitsB64)
    } else if (typeof bitsB64 === 'string') {
        result = b64ToArray(bitsB64)
    } else if (bitsB64 == null) {
        result = webcrypto.getRandomValues(new Uint8Array(16))
    } else {
        throw new Error('Must be Uint8Array, string, or nullish')
    }

    if (result.byteLength !== 16) {
        throw new Error('Invalid byteLength: must be 16 bytes')
    }

    return result
}
