import * as u from 'uint8arrays'
import { test } from '@substrate-system/tapzero'
import { Keychain } from '../src/index.js'

let keychain:InstanceType<typeof Keychain>
let salt:Uint8Array
let encrypted:Uint8Array
let keyString:string
let saltString:string
test('Encrypt a blob (not stream)', async t => {
    keychain = new Keychain()
    keyString = keychain.keyB64
    saltString = keychain.saltB64
    salt = keychain.salt
    const data = 'hello world'

    const encData = encrypted = await keychain.encryptBytes(u.fromString(data))
    t.ok(encData instanceof Uint8Array, 'should return a Uint8Array')

    const decData = await keychain.decryptBytes(encData)
    t.equal(u.toString(new Uint8Array(decData)), 'hello world',
        'Should decrypt to the same value')
})

test('create another keychain and decrypt', async t => {
    const newKeys = new Keychain(keyString, saltString)
    const decData = await newKeys.decryptBytes(encrypted)
    t.equal(u.toString(new Uint8Array(decData)), 'hello world',
        'Can create a new keychain and decrypt the data')
})

test('encryptBytes + decryptBytes with a custom key size', async t => {
    const keychain = new Keychain()
    const data = 'hello world, with a 32-byte key'

    const encData = await keychain.encryptBytes(u.fromString(data), {
        size: 32
    })
    const decData = await keychain.decryptBytes(encData, { size: 32 })

    t.equal(u.toString(new Uint8Array(decData)), data,
        'should decrypt when the same size is passed to both')
})
