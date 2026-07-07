import * as u from 'uint8arrays'
import {
    DEFAULT_KEY_ENCODING,
    MAIN_KEY_LENGTHS,
    KEY_LENGTH
} from './constants.js'

export function generateSalt (len:number):Uint8Array<ArrayBuffer> {
    const salt = new Uint8Array(len)
    webcrypto.getRandomValues(salt)
    return salt
}

export type Salt = string|Uint8Array

const webcrypto = globalThis.crypto

/**
 * Return a `Uint8Array` of the given length filled with random bytes.
 * @param length Number of random bytes to return
 * @returns {Uint8Array<ArrayBuffer>}
 */
export function randomBuf (length:number):Uint8Array<ArrayBuffer> {
    return webcrypto.getRandomValues(new Uint8Array(length))
}

/**
 * Concatenate two buffers into a single `Uint8Array`.
 * @param fst The first buffer
 * @param snd The second buffer
 * @returns {Uint8Array<ArrayBuffer>}
 */
export function joinBufs (
    fst:ArrayBuffer|Uint8Array,
    snd:ArrayBuffer|Uint8Array
):Uint8Array<ArrayBuffer> {
    const view1 = new Uint8Array(fst)
    const view2 = new Uint8Array(snd)
    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined
}

/**
 * Return a `Uint8Array` backed by a plain `ArrayBuffer`.
 *
 * The WebCrypto and `Blob` APIs require a `BufferSource` backed by an
 * `ArrayBuffer`, but the default `Uint8Array` type is backed by
 * `ArrayBufferLike` (which includes `SharedArrayBuffer`). Copy only when
 * the backing buffer is not already a plain `ArrayBuffer`.
 *
 * @param data The buffer to coerce
 * @returns {Uint8Array<ArrayBuffer>}
 */
export function asBufferSource (
    data:ArrayBuffer|Uint8Array
):Uint8Array<ArrayBuffer> {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data)
    }
    if (data.buffer instanceof ArrayBuffer) {
        return data as Uint8Array<ArrayBuffer>
    }
    return new Uint8Array(data)
}

export function arrayToB64 (array:Uint8Array):string {
    return u.toString(array, 'base64url')
}

/**
 * Return the given Uint8Array as a base64url string.
 * @param array Uint8Array
 * @returns `base64url` encoded string
 */
export function arrayToB64Url (array:Uint8Array):string {
    return u.toString(array, 'base64url')
}

export function b64ToArray (str:string):Uint8Array<ArrayBuffer> {
    return u.fromString(str, 'base64url')
}

export type KeychainOptions = {
    salt?:Salt|null;
    encoding?:u.SupportedEncodings;
}

export function normalizeKeychainOptions (
    options?:KeychainOptions|Salt|null
):KeychainOptions {
    if (
        options == null ||
        typeof options === 'string' ||
        options instanceof Uint8Array
    ) {
        return { salt: options }
    }

    return options
}

export function decodeMainKey (
    key?:Uint8Array|string|null,
    encoding:u.SupportedEncodings = DEFAULT_KEY_ENCODING
):Uint8Array<ArrayBuffer> {
    return decodeBits(key, 'key', MAIN_KEY_LENGTHS, encoding)
}

export function decodeBits (
    bitsB64?:Uint8Array|string|null,
    name = 'value',
    validLengths = [KEY_LENGTH],
    encoding:u.SupportedEncodings = DEFAULT_KEY_ENCODING
):Uint8Array<ArrayBuffer> {
    let result
    if (bitsB64 instanceof Uint8Array) {
        result = asBufferSource(bitsB64)
    } else if (typeof bitsB64 === 'string') {
        result = u.fromString(bitsB64, encoding)
    } else if (bitsB64 == null) {
        result = webcrypto.getRandomValues(new Uint8Array(16))
    } else {
        throw new Error('Must be Uint8Array, string, or nullish')
    }

    if (!validLengths.includes(result.byteLength)) {
        const lengths = validLengths
            .map(length => `${length} bytes`)
            .join(' or ')
        throw new Error(`Invalid ${name} byteLength: must be ${lengths}`)
    }

    return result
}
