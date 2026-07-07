import { test } from '@substrate-system/tapzero'
import * as u from 'uint8arrays'
import { Keychain } from '../src/index.js'
import './metadata.js'
import './stream.js'
import './bytes.js'
import './seekable-write.js'

const webcrypto = globalThis.crypto

let keychain:InstanceType<typeof Keychain>
let salt:Uint8Array
test('keychain properties', async t => {
    keychain = new Keychain()
    salt = keychain.salt

    t.ok(keychain.key instanceof Uint8Array)
    t.equal(keychain.key.byteLength, 16)

    t.ok(keychain.salt instanceof Uint8Array)
    t.equal(keychain.salt.byteLength, 16)

    t.equal(typeof keychain.keyB64, 'string')
    t.equal(keychain.keyB64.length, 22)

    t.equal(typeof keychain.saltB64, 'string')
    t.equal(keychain.saltB64.length, 24)

    const authToken = await keychain.authToken()
    t.ok(authToken instanceof Uint8Array)
    t.equal(authToken.byteLength, 16)

    const authTokenB64 = await keychain.authTokenB64()
    t.equal(typeof authTokenB64, 'string')
    t.equal(authTokenB64.length, 24)

    const authHeader = await keychain.authHeader()
    t.equal(typeof authHeader, 'string')
    t.equal(authHeader, `Bearer sync-v1 ${authTokenB64}`)
})

test('auth tokens', async t => {
    // generate a new key, re-use the same salt
    const newKeychain = new Keychain(undefined, salt)
    const oldKey = keychain.keyB64
    const newKey = newKeychain.keyB64
    t.ok(oldKey !== newKey, 'should have different keys')
    t.ok(keychain.saltB64 === newKeychain.saltB64, 'should have the same salt')
    const tokens = await Promise.all([
        keychain.authTokenB64(),
        newKeychain.authTokenB64()
    ])

    t.ok(tokens[0] !== tokens[1],
        'should get a different token given different keys')
})

test('keychain from given key and salt (Uint8Array)', async t => {
    const key = webcrypto.getRandomValues(new Uint8Array(16))
    const salt = webcrypto.getRandomValues(new Uint8Array(16))

    const keychain = new Keychain(key, salt)

    t.deepEqual(keychain.key, key)
    t.deepEqual(keychain.salt, salt)
})

test('keychain from given key and salt (base64)', async t => {
    const key = webcrypto.getRandomValues(new Uint8Array(16))
    const salt = webcrypto.getRandomValues(new Uint8Array(16))

    const keychain = new Keychain(
        u.toString(key, 'base64pad'),
        u.toString(salt, 'base64pad')
    )

    t.deepEqual(keychain.key, key)
    t.deepEqual(keychain.salt, salt)
})

test('keychain throws on invalid key or salt', async t => {
    t.throws(() => {
        // eslint-disable-next-line no-new
        new Keychain(new Uint8Array(15), new Uint8Array(16))
    })
    t.throws(() => {
        // eslint-disable-next-line no-new
        new Keychain(new Uint8Array(16), new Uint8Array(17))
    })
    t.throws(() => {
        // @ts-ignore
        new Keychain([])  // eslint-disable-line no-new
    })
    t.throws(() => {
        // @ts-ignore
        new Keychain({})  // eslint-disable-line no-new
    })
    t.throws(() => {
        // @ts-ignore
        new Keychain(10)  // eslint-disable-line no-new
    })
    t.throws(() => {
        // @ts-ignore
        new Keychain(true)  // eslint-disable-line no-new
    })
})

test('keychain.setAuthTokenB64', async t => {
    const keychain = new Keychain()
    const authToken = webcrypto.getRandomValues(new Uint8Array(16))
    keychain.setAuthToken(authToken)

    t.deepEqual(await keychain.authToken(), authToken)
    t.equal(await keychain.authTokenB64(), u.toString(authToken, 'base64pad'))
})

test('.AuthHeader static method', async t => {
    const newKeys = new Keychain()
    const stringMainKey = newKeys.keyB64
    const authHeader = await Keychain.AuthHeader(stringMainKey, newKeys.saltB64)

    t.equal(typeof authHeader, 'string', 'should return a string')
    t.ok(authHeader.includes('Bearer'), 'should be the right format')

    const otherHeader = await newKeys.authHeader()
    t.equal(otherHeader, authHeader,
        'should be equal to the instance method, given the same keys')
})

test('.Header static method', async t => {
    const header = Keychain.Header('123')
    t.equal(header, 'Bearer sync-v1 123', 'should return the right format')
})
