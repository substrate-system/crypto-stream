import { test } from '@substrate-system/tapzero'
import {
    RECORD_SIZE,
    HEADER_LENGTH,
    KEY_LENGTH,
    recordPlaintextSize,
    recordCount,
    header,
    encryptStream,
    decryptStream as eceDecryptStream,
    deriveContentSalt,
    encryptRecord,
    plaintextSize
} from '../src/ece.js'
import * as root from '../src/index.js'

const webcrypto = globalThis.crypto

// Build the HKDF CryptoKey that ece functions expect as `secretKey`.
async function makeKey (
    bytes:Uint8Array = webcrypto.getRandomValues(new Uint8Array(16))
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'raw',
        bytes as BufferSource,
        'HKDF',
        false,
        ['deriveBits', 'deriveKey']
    )
}

function arrayToStream (array:Uint8Array):ReadableStream<Uint8Array> {
    return new ReadableStream({
        pull (controller) {
            controller.enqueue(array)
            controller.close()
        }
    })
}

async function streamToArray (
    stream:ReadableStream<Uint8Array>
):Promise<Uint8Array> {
    const response = new Response(stream)
    return new Uint8Array(await response.arrayBuffer())
}

// Export surface tests (AC6)
test('exports: RECORD_SIZE', t => {
    t.equal(typeof RECORD_SIZE, 'number')
})

test('exports: HEADER_LENGTH', t => {
    t.equal(typeof HEADER_LENGTH, 'number')
    t.equal(HEADER_LENGTH, 21)
})

test('header: rejects record size smaller than RFC minimum', t => {
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    t.throws(() => header(salt, 17), /rs must be at least 18/)
})

test('exports: recordPlaintextSize', t => {
    t.equal(typeof recordPlaintextSize, 'function')
})

test('exports: recordCount', t => {
    t.equal(typeof recordCount, 'function')
})

test('exports: header', t => {
    t.equal(typeof header, 'function')
})

test('root exports: should not have seekable-write exports', t => {
    const names = [
        'RECORD_SIZE',
        'HEADER_LENGTH',
        'recordPlaintextSize',
        'recordCount',
        'header',
        'deriveContentSalt',
        'encryptRecord'
    ]
    for (const name of names) {
        t.equal(
            typeof (root as Record<string, unknown>)[name],
            'undefined',
            `root.${name} should be undefined`
        )
    }
})

// Geometry tests (AC4)
test('recordPlaintextSize: default record size', t => {
    const result = recordPlaintextSize()
    t.equal(result, RECORD_SIZE - 17)
    t.equal(result, 65519)
})

test('recordPlaintextSize: custom record size', t => {
    const result = recordPlaintextSize(1024)
    t.equal(result, 1007)
})

test('recordCount: n=1 with custom rs', t => {
    const rs = 1024
    const n = 1
    const result = recordCount(n, rs)
    t.equal(result, 1)
})

test('recordCount: n=rs-17 with custom rs', t => {
    const rs = 1024
    const n = rs - 17
    const result = recordCount(n, rs)
    t.equal(result, 1)
})

test('recordCount: n=(rs-17)+1 with custom rs', t => {
    const rs = 1024
    const n = (rs - 17) + 1
    const result = recordCount(n, rs)
    t.equal(result, 2)
})

test('recordCount: zero plaintext with default rs', t => {
    const result = recordCount(0)
    t.equal(result, 0)
})

test('recordCount: zero plaintext with custom rs', t => {
    const result = recordCount(0, 1024)
    t.equal(result, 0)
})

test('recordCount: k*(rs-17) records with custom rs', t => {
    const rs = 1024
    const k = 3
    const n = k * (rs - 17)
    const result = recordCount(n, rs)
    t.equal(result, k)
})

test('plaintextSize: throws for encryptedSize smaller than HEADER_LENGTH', t => {
    t.throws(() => plaintextSize(HEADER_LENGTH - 1))
    t.throws(() => plaintextSize(0))
})

test('plaintextSize: does not throw for encryptedSize === HEADER_LENGTH', t => {
    const result = plaintextSize(HEADER_LENGTH)
    t.equal(result, 0)
})

// Header equality test (AC3.1)
test('header: matches encryptStream output', async t => {
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const rs = 4096
    const key = await makeKey()

    // Build standalone header
    const standaloneHeader = header(salt, rs)

    // Build encrypted stream with same salt and rs
    const plaintext = new Uint8Array([1, 2, 3, 4, 5])
    const encrypted = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    // Extract first 21 bytes from encrypted stream
    const streamHeader = encrypted.slice(0, HEADER_LENGTH)

    // Compare
    t.deepEqual(standaloneHeader, streamHeader)
})

// deriveContentSalt tests (AC2.3, AC2.2, AC5.3)
test('deriveContentSalt: deterministic for same (key, digest)', async t => {
    const key = await makeKey()
    const digest = new Uint8Array(32).fill(7)

    const salt1 = await deriveContentSalt(key, digest)
    const salt2 = await deriveContentSalt(key, digest)

    t.equal(salt1.byteLength, 16)
    t.equal(salt2.byteLength, 16)
    t.deepEqual(salt1, salt2)
})

test('deriveContentSalt: different digests yield different salts', async t => {
    const key = await makeKey()
    const digest1 = new Uint8Array(32).fill(1)
    const digest2 = new Uint8Array(32).fill(2)

    const salt1 = await deriveContentSalt(key, digest1)
    const salt2 = await deriveContentSalt(key, digest2)

    t.equal(salt1.byteLength, 16)
    t.equal(salt2.byteLength, 16)
    const equal = salt1.every((v, i) => v === salt2[i])
    t.ok(!equal, 'different digests should produce different salts')
})

test('deriveContentSalt: rejects empty digest', async t => {
    const key = await makeKey()
    const emptyDigest = new Uint8Array(0)

    await t.throws(async () => {
        await deriveContentSalt(key, emptyDigest)
    })
})

// encryptRecord tests (AC5.1, AC5.2, AC5.4)
test('encryptRecord: non-final record with wrong length throws', async t => {
    const key = await makeKey()
    const rs = 64
    const max = recordPlaintextSize(rs)
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const slice = new Uint8Array(max - 1)

    await t.throws(async () => {
        await encryptRecord(key, 0, slice, false, salt, rs)
    })
})

test('encryptRecord: final record with oversized slice throws', async t => {
    const key = await makeKey()
    const rs = 64
    const max = recordPlaintextSize(rs)
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const slice = new Uint8Array(max + 1)

    await t.throws(async () => {
        await encryptRecord(key, 0, slice, true, salt, rs)
    })
})

test('encryptRecord: non-16-byte salt throws Invalid salt length', async t => {
    const key = await makeKey()
    const rs = 64
    const max = recordPlaintextSize(rs)
    const slice = new Uint8Array(max)
    const badSalt = new Uint8Array(15)

    await t.throws(async () => {
        await encryptRecord(key, 0, slice, false, badSalt, rs)
    }, /Invalid salt length/)
})

test('encryptRecord: accepts sequence numbers beyond 32 bits', async t => {
    const key = await makeKey()
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const plaintext = new Uint8Array([1, 2, 3])

    const encrypted = await encryptRecord(
        key,
        0x100000000,
        plaintext,
        true,
        salt
    )

    t.ok(encrypted instanceof Uint8Array)
})

// Helper to build per-record ciphertext
async function buildPerRecordCiphertext (
    plaintext:Uint8Array,
    key:CryptoKey,
    salt:Uint8Array<ArrayBuffer>,
    rs:number
):Promise<Uint8Array> {
    const max = recordPlaintextSize(rs)
    const count = recordCount(plaintext.byteLength, rs)

    const chunks:Array<Uint8Array> = []

    chunks.push(header(salt, rs))

    for (let i = 0; i < count; i++) {
        const start = i * max
        const end = Math.min(start + max, plaintext.byteLength)
        const slice = plaintext.subarray(start, end)
        const isLast = i === count - 1

        const encrypted = await encryptRecord(key, i, slice, isLast, salt, rs)
        chunks.push(encrypted)
    }

    const totalSize = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
    const result = new Uint8Array(totalSize)
    let offset = 0
    for (const chunk of chunks) {
        result.set(chunk, offset)
        offset += chunk.byteLength
    }

    return result
}

// Helper to decrypt using ece.decryptStream directly
function decryptStreamECE (
    stream:ReadableStream<Uint8Array>,
    key:CryptoKey,
    rs:number = RECORD_SIZE
):ReadableStream<Uint8Array> {
    return eceDecryptStream(stream, key, rs)
}

// Record/stream equivalence tests (AC3.2, AC4.4)
test('record/stream equivalence: partial final record', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const plaintext = new Uint8Array(100)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

test('record/stream equivalence: single full record', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const plaintext = new Uint8Array(max)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

test('record/stream equivalence: multiple records non-multiple', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const plaintext = new Uint8Array(max * 2 + 50)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

test('record/stream equivalence: exact multiple (k*(rs-17))', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const k = 3
    const plaintext = new Uint8Array(k * max)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

// Round-trip test (AC3.3)
test('record/stream: round-trip decryption', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const plaintext = new Uint8Array(max * 2 + 50)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)

    const decrypted = await streamToArray(
        decryptStreamECE(arrayToStream(perRecord), key, rs)
    )

    t.deepEqual(decrypted, plaintext)
})

// Export surface completion test (AC6.1)
test('exports: deriveContentSalt', t => {
    t.equal(typeof deriveContentSalt, 'function')
})

test('exports: encryptRecord', t => {
    t.equal(typeof encryptRecord, 'function')
})

// Keychain.contentDigest tests (Task 1 - AC2.1, AC2.4, AC2.2)
test('Keychain.contentDigest: returns 32-byte array for Uint8Array',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const digest = await keychain.contentDigest(data)

        t.equal(digest.byteLength, 32)
        t.ok(digest instanceof Uint8Array)
    }
)

test('Keychain.contentDigest: same input yields same digest',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])

        const digest1 = await keychain.contentDigest(data)
        const digest2 = await keychain.contentDigest(data)

        t.deepEqual(digest1, digest2)
    }
)

test('Keychain.contentDigest: Uint8Array, stream, Blob equal',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])

        const digestBytes = await keychain.contentDigest(data)
        const digestStream = await keychain.contentDigest(arrayToStream(data))
        const digestBlob = await keychain.contentDigest(new Blob([data]))

        t.deepEqual(digestBytes, digestStream)
        t.deepEqual(digestBytes, digestBlob)
    }
)

test('Keychain.contentDigest: different plaintexts yield different digests',
    async t => {
        const keychain = new root.Keychain()
        const data1 = new Uint8Array([1, 2, 3, 4, 5])
        const data2 = new Uint8Array([6, 7, 8, 9, 10])

        const digest1 = await keychain.contentDigest(data1)
        const digest2 = await keychain.contentDigest(data2)

        const equal = digest1.every((v, i) => v === digest2[i])
        t.ok(!equal, 'different plaintexts should yield different digests')
    }
)

test(
    'Keychain.contentDigest: different digests → different salts',
    async t => {
        const key = await makeKey()
        const keychain = new root.Keychain()
        const data1 = new Uint8Array([1, 2, 3, 4, 5])
        const data2 = new Uint8Array([6, 7, 8, 9, 10])

        const digest1 = await keychain.contentDigest(data1)
        const digest2 = await keychain.contentDigest(data2)

        const salt1 = await deriveContentSalt(key, digest1)
        const salt2 = await deriveContentSalt(key, digest2)

        const equal = salt1.every((v, i) => v === salt2[i])
        t.ok(!equal, 'different digests should produce different salts')
    }
)

// Keychain.encryptStream reproducible tests (Task 2)
test(
    'Keychain.encryptStream: reproducible with contentDigest',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const digest = await keychain.contentDigest(data)

        const encrypted1 = await streamToArray(
            await keychain.encryptStream(arrayToStream(data), {
                contentDigest: digest
            })
        )
        const encrypted2 = await streamToArray(
            await keychain.encryptStream(arrayToStream(data), {
                contentDigest: digest
            })
        )

        t.deepEqual(encrypted1, encrypted2)
    }
)

test(
    'Keychain.encryptStream: random salt without options',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])

        const encrypted1 = await streamToArray(
            await keychain.encryptStream(arrayToStream(data))
        )
        const encrypted2 = await streamToArray(
            await keychain.encryptStream(arrayToStream(data))
        )

        const equal = encrypted1.every((v, i) => v === encrypted2[i])
        t.ok(!equal, 'random salt should produce different outputs')
    }
)

test(
    'Keychain.encryptStream: random salt round-trip',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])

        const encrypted = await streamToArray(
            await keychain.encryptStream(arrayToStream(data))
        )

        const decrypted = await streamToArray(
            await keychain.decryptStream(arrayToStream(encrypted))
        )

        t.deepEqual(decrypted, data)
    }
)

test(
    'Keychain.encryptStream: recordSize honored',
    async t => {
        const keychain = new root.Keychain()
        const rs = 256
        const data = new Uint8Array(1000)
        webcrypto.getRandomValues(data)

        const encrypted = await streamToArray(
            await keychain.encryptStream(
                arrayToStream(data),
                { recordSize: rs }
            )
        )

        const expectedSize = root.encryptedSize(data.length, rs)
        t.equal(encrypted.length, expectedSize)
    }
)

test(
    'Keychain.decryptStream: reads custom recordSize from header',
    async t => {
        const keychain = new root.Keychain()
        const rs = 256
        const data = new Uint8Array(1000)
        webcrypto.getRandomValues(data)

        const encrypted = await streamToArray(
            await keychain.encryptStream(
                arrayToStream(data),
                { recordSize: rs }
            )
        )

        const decrypted = await streamToArray(
            await keychain.decryptStream(arrayToStream(encrypted))
        )

        t.deepEqual(decrypted, data)
    }
)

test(
    'ece.decryptStream: accepts non-zero keyid header',
    async t => {
        const key = await makeKey()
        const salt = webcrypto.getRandomValues(new Uint8Array(16))
        const rs = 256
        const data = new Uint8Array(1000)
        const keyid = new TextEncoder().encode('kid')
        webcrypto.getRandomValues(data)

        const encrypted = await streamToArray(
            encryptStream(arrayToStream(data), key, rs, salt)
        )
        const cipher = new Uint8Array(encrypted.byteLength + keyid.byteLength)
        cipher.set(encrypted.slice(0, HEADER_LENGTH), 0)
        cipher[KEY_LENGTH + 4] = keyid.byteLength
        cipher.set(keyid, HEADER_LENGTH)
        cipher.set(
            encrypted.slice(HEADER_LENGTH),
            HEADER_LENGTH + keyid.byteLength
        )

        const decrypted = await streamToArray(
            eceDecryptStream(arrayToStream(cipher), key)
        )

        t.deepEqual(decrypted, data)
    }
)

test(
    'Keychain.encryptStream: empty input with contentDigest',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array(0)
        const digest = await keychain.contentDigest(data)

        const encrypted = await streamToArray(
            await keychain.encryptStream(arrayToStream(data), {
                contentDigest: digest
            })
        )

        t.equal(encrypted.length, HEADER_LENGTH)
    }
)

// Task 1: Keychain.header tests (AC3.4, AC4.3)
test(
    'Keychain.header: returns 21-byte array',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const digest = await keychain.contentDigest(data)

        const hdr = await keychain.header({ contentDigest: digest })

        t.equal(hdr.byteLength, HEADER_LENGTH)
        t.ok(hdr instanceof Uint8Array)
    }
)

test(
    'Keychain.header: matches encryptStream output header',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const digest = await keychain.contentDigest(data)
        const rs = 256

        const hdr = await keychain.header({
            contentDigest: digest,
            recordSize: rs
        })

        const encrypted = await streamToArray(
            await keychain.encryptStream(arrayToStream(data), {
                contentDigest: digest,
                recordSize: rs
            })
        )

        const streamHeader = encrypted.slice(0, HEADER_LENGTH)
        t.deepEqual(hdr, streamHeader)
    }
)

// Task 2: Keychain.encryptRecord tests (AC3.4)
test(
    'Keychain.encryptRecord: encrypts record',
    async t => {
        const keychain = new root.Keychain()
        const rs = 256
        const max = recordPlaintextSize(rs)
        const plaintext = new Uint8Array(max)
        webcrypto.getRandomValues(plaintext)
        const digest = await keychain.contentDigest(plaintext)

        const encrypted = await keychain.encryptRecord(
            0,
            plaintext,
            {
                isLast: true,
                contentDigest: digest,
                recordSize: rs
            }
        )

        t.ok(encrypted instanceof Uint8Array)
        t.ok(encrypted.byteLength > 0)
    }
)

test(
    'Keychain.encryptRecord: matches ece.encryptRecord',
    async t => {
        const keychain = new root.Keychain()
        const rs = 256
        const max = recordPlaintextSize(rs)
        const plaintext = new Uint8Array(max)
        webcrypto.getRandomValues(plaintext)
        const digest = await keychain.contentDigest(plaintext)

        const keychainEncrypted = await keychain.encryptRecord(
            0,
            plaintext,
            {
                isLast: true,
                contentDigest: digest,
                recordSize: rs
            }
        )

        const salt = await deriveContentSalt(
            await keychain['mainKeyPromise'],
            digest
        )
        const eceEncrypted = await encryptRecord(
            await keychain['mainKeyPromise'],
            0,
            plaintext,
            true,
            salt,
            rs
        )

        t.deepEqual(keychainEncrypted, eceEncrypted)
    }
)

// Task 3: Round-trip tests (AC3.3, AC3.4, AC4.3)
test(
    'Keychain round-trip: single record (default rs)',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array([1, 2, 3, 4, 5])
        const digest = await keychain.contentDigest(data)

        const hdr = await keychain.header({ contentDigest: digest })
        const max = recordPlaintextSize(RECORD_SIZE)
        const n = recordCount(data.length, RECORD_SIZE)

        const chunks:Array<Uint8Array> = [hdr]

        for (let i = 0; i < n; i++) {
            const start = i * max
            const end = Math.min(start + max, data.length)
            const slice = data.subarray(start, end)
            const encrypted = await keychain.encryptRecord(
                i,
                slice,
                {
                    isLast: i === n - 1,
                    contentDigest: digest
                }
            )
            chunks.push(encrypted)
        }

        const totalSize = chunks.reduce(
            (sum, chunk) => sum + chunk.byteLength,
            0
        )
        const cipher = new Uint8Array(totalSize)
        let offset = 0
        for (const chunk of chunks) {
            cipher.set(chunk, offset)
            offset += chunk.byteLength
        }

        const decrypted = await streamToArray(
            await keychain.decryptStream(arrayToStream(cipher))
        )

        t.deepEqual(decrypted, data)
    }
)

test(
    'Keychain round-trip: multiple records (small rs)',
    async t => {
        const keychain = new root.Keychain()
        const rs = 128
        const data = new Uint8Array(300)
        webcrypto.getRandomValues(data)
        const digest = await keychain.contentDigest(data)

        const hdr = await keychain.header({
            contentDigest: digest,
            recordSize: rs
        })
        const max = recordPlaintextSize(rs)
        const n = recordCount(data.length, rs)

        const chunks:Array<Uint8Array> = [hdr]

        for (let i = 0; i < n; i++) {
            const start = i * max
            const end = Math.min(start + max, data.length)
            const slice = data.subarray(start, end)
            const encrypted = await keychain.encryptRecord(
                i,
                slice,
                {
                    isLast: i === n - 1,
                    contentDigest: digest,
                    recordSize: rs
                }
            )
            chunks.push(encrypted)
        }

        const totalSize = chunks.reduce(
            (sum, chunk) => sum + chunk.byteLength,
            0
        )
        const cipher = new Uint8Array(totalSize)
        let offset = 0
        for (const chunk of chunks) {
            cipher.set(chunk, offset)
            offset += chunk.byteLength
        }

        const decrypted = await streamToArray(
            await keychain.decryptStream(arrayToStream(cipher), {
                recordSize: rs
            })
        )

        t.deepEqual(decrypted, data)
    }
)

test(
    'Keychain round-trip: custom rs via decryptStreamRange',
    async t => {
        const keychain = new root.Keychain()
        const rs = 128
        const data = new Uint8Array(300)
        webcrypto.getRandomValues(data)
        const digest = await keychain.contentDigest(data)

        const hdr = await keychain.header({
            contentDigest: digest,
            recordSize: rs
        })
        const max = recordPlaintextSize(rs)
        const n = recordCount(data.length, rs)

        const chunks:Array<Uint8Array> = [hdr]
        for (let i = 0; i < n; i++) {
            const start = i * max
            const end = Math.min(start + max, data.length)
            const slice = data.subarray(start, end)
            const encrypted = await keychain.encryptRecord(
                i,
                slice,
                {
                    isLast: i === n - 1,
                    contentDigest: digest,
                    recordSize: rs
                }
            )
            chunks.push(encrypted)
        }

        const totalSize = chunks.reduce(
            (sum, chunk) => sum + chunk.byteLength,
            0
        )
        const cipher = new Uint8Array(totalSize)
        let offset = 0
        for (const chunk of chunks) {
            cipher.set(chunk, offset)
            offset += chunk.byteLength
        }

        const rangeOffset = 50
        const rangeLength = 100
        const { ranges, decrypt } = await keychain.decryptStreamRange(
            rangeOffset,
            rangeLength,
            cipher.byteLength,
            { recordSize: rs }
        )

        const streams = ranges.map(({ offset, length }) =>
            arrayToStream(cipher.slice(offset, offset + length))
        )

        const decrypted = await streamToArray(decrypt(streams))

        t.deepEqual(decrypted, data.slice(rangeOffset, rangeOffset + rangeLength))
    }
)

test(
    'Keychain round-trip: empty input',
    async t => {
        const keychain = new root.Keychain()
        const data = new Uint8Array(0)
        const digest = await keychain.contentDigest(data)

        const hdr = await keychain.header({
            contentDigest: digest
        })
        const n = recordCount(data.length)

        t.equal(n, 0, 'empty input should have 0 records')

        const cipher = hdr

        const decrypted = await streamToArray(
            await keychain.decryptStream(arrayToStream(cipher))
        )

        t.equal(decrypted.length, 0)
    }
)
