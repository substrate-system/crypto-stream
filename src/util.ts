export function generateSalt (len:number):Uint8Array<ArrayBuffer> {
    const salt = new Uint8Array(len)
    webcrypto.getRandomValues(salt)
    return salt
}

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
