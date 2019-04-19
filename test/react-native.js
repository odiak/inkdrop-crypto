// @flow
import createEncryptHelper from '../src'
import test from 'ava'
import crypto from 'crypto-browserify'
const iter = 100000

test('check exports', t => {
  t.is(typeof createEncryptHelper, 'function')
})

test('generating encryption key', t => {
  const mod = createEncryptHelper(crypto)
  const keyMasked = mod.createEncryptionKey('foo', iter)
  t.is(keyMasked.algorithm, 'aes-256-gcm')
  t.is(typeof keyMasked.content, 'string')
  t.is(typeof keyMasked.iv, 'string')
  t.is(typeof keyMasked.tag, 'string')
  t.is(typeof keyMasked.salt, 'string')

  const key = mod.revealEncryptionKey('foo', keyMasked, iter)
  t.is(typeof key, 'string')
})

test('updating encryption key', t => {
  const mod = createEncryptHelper(crypto)
  const keyMasked = mod.createEncryptionKey('foo', iter)

  const keyUpdated = mod.updateEncryptionKey(
    'foo',
    iter,
    'bar',
    iter,
    keyMasked
  )
  t.is(keyUpdated.algorithm, 'aes-256-gcm')
  t.is(typeof keyUpdated.content, 'string')
  t.is(typeof keyUpdated.iv, 'string')
  t.is(typeof keyUpdated.tag, 'string')
  t.is(typeof keyUpdated.salt, 'string')
  t.is(keyMasked.content !== keyUpdated.content, true)
  t.is(keyMasked.iv !== keyUpdated.iv, true)
  t.is(keyMasked.tag !== keyUpdated.tag, true)
  t.is(keyMasked.salt === keyUpdated.salt, true)

  const key = mod.revealEncryptionKey('bar', keyUpdated, iter)
  t.is(typeof key, 'string')
})

test('encrypt & decrypt document', t => {
  const mod = createEncryptHelper(crypto)
  const pass = 'foo'
  const keyMasked = mod.createEncryptionKey(pass, iter)
  const key = mod.revealEncryptionKey(pass, keyMasked, iter)
  const note = {
    _id: 'note:test',
    title: 'title',
    body: '# This is markdown',
    bookId: 'book:test',
    tags: [],
    createdAt: +new Date(),
    updatedAt: +new Date()
  }
  const noteEnc = mod.encryptDoc(key, note)

  t.is(typeof noteEnc.encryptedData, 'object')
  t.is(typeof noteEnc.encryptedData.algorithm, 'string')
  t.is(typeof noteEnc.encryptedData.content, 'string')
  t.is(typeof noteEnc.encryptedData.iv, 'string')
  t.is(typeof noteEnc.encryptedData.tag, 'string')
  t.is(noteEnc.title, undefined)
  t.is(noteEnc.body, undefined)

  const noteDec = mod.decryptDoc(key, noteEnc)
  t.is(noteDec._id, note._id)
  t.is(noteDec.title, note.title)
  t.is(noteDec.body, note.body)
  t.is(noteDec.bookId, note.bookId)
})
