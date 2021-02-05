// @flow
import {
  createEncryptHelperForRN,
  type AesGcmEncryptedData,
  EncryptError,
  DecryptError
} from '../src'
import test from 'ava'
import crypto from 'crypto'
const iter = 100000
const algorithm = 'aes-256-gcm'

global.require = require

const cryptoMock = {
  async decrypt(
    base64Ciphertext: string,
    key: string,
    ivStr: string,
    tag: string,
    isBinary: boolean
  ): Promise<string> {
    if (typeof key !== 'string') {
      throw new DecryptError('Invalid key. it must be a String')
    }
    const iv = Buffer.from(ivStr, 'hex')
    const decipher = crypto.createDecipheriv(algorithm, key, iv)
    decipher.setAuthTag(Buffer.from(tag, 'hex'))
    const outputEncoding = isBinary ? undefined : 'utf8'
    let decrypted = decipher.update(base64Ciphertext, 'base64', outputEncoding)
    if (isBinary && decrypted instanceof Buffer) {
      const final = decipher.final()
      decrypted = Buffer.concat([decrypted, final])
      return decrypted.toString('base64')
    } else if (typeof decrypted === 'string') {
      const final = decipher.final('utf8')
      return decrypted + final
    } else {
      throw new DecryptError('Failed to decrypt')
    }
  },

  async encrypt(
    plainText: string,
    inBinary: boolean,
    key: string
  ): Promise<AesGcmEncryptedData> {
    if (typeof key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv(algorithm, key, iv)

    const inputEncoding = inBinary ? 'binary' : 'utf8'
    const inputData = inBinary ? Buffer.from(plainText, 'base64') : plainText
    let encrypted = cipher.update(inputData, inputEncoding, 'base64')
    encrypted += cipher.final('base64')
    const tag = cipher.getAuthTag()

    return {
      algorithm,
      content: encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    }
  }
}

const md5Mock = {
  calc(
    content: string,
    inputEncoding: 'utf8' | 'base64',
    outputEncoding: 'hex' | 'base64'
  ): string {
    return crypto.createHash('md5').update(content).digest(outputEncoding)
  }
}

test('check exports', t => {
  t.is(typeof createEncryptHelperForRN, 'function')
})

test('generating encryption key', async t => {
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock)
  const keyMasked = await mod.createEncryptionKey('foo', iter)
  t.log('keyMasked:', keyMasked)
  t.is(keyMasked.algorithm, 'aes-256-gcm')
  t.is(typeof keyMasked.content, 'string')
  t.is(typeof keyMasked.iv, 'string')
  t.is(typeof keyMasked.tag, 'string')
  t.is(typeof keyMasked.salt, 'string')
  t.is(typeof keyMasked.iterations, 'number')

  const key = await mod.revealEncryptionKey('foo', keyMasked)
  t.is(typeof key, 'string')
})

test('updating encryption key', async t => {
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock)
  const keyMasked = await mod.createEncryptionKey('foo', iter)

  const keyUpdated = await mod.updateEncryptionKey(
    'foo',
    'bar',
    iter,
    keyMasked
  )
  t.is(keyUpdated.algorithm, 'aes-256-gcm')
  t.is(typeof keyUpdated.content, 'string')
  t.is(typeof keyUpdated.iv, 'string')
  t.is(typeof keyUpdated.tag, 'string')
  t.is(typeof keyUpdated.salt, 'string')
  t.is(typeof keyUpdated.iterations, 'number')
  t.is(keyMasked.content !== keyUpdated.content, true)
  t.is(keyMasked.iv !== keyUpdated.iv, true)
  t.is(keyMasked.tag !== keyUpdated.tag, true)
  t.is(keyMasked.salt === keyUpdated.salt, true)

  const key = await mod.revealEncryptionKey('bar', keyUpdated)
  t.is(typeof key, 'string')
})

test('encrypt & decrypt document', async t => {
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock)
  const pass = 'foo'
  const keyMasked = await mod.createEncryptionKey(pass, iter)
  const key = await mod.revealEncryptionKey(pass, keyMasked)
  const note = {
    _id: 'note:test',
    title: 'title',
    body: '# This is markdown',
    bookId: 'book:test',
    tags: [],
    createdAt: +new Date(),
    updatedAt: +new Date()
  }
  const noteEnc = await mod.encryptDoc(key, note)

  t.is(typeof noteEnc.encryptedData, 'object')
  t.is(typeof noteEnc.encryptedData.algorithm, 'string')
  t.is(typeof noteEnc.encryptedData.content, 'string')
  t.is(typeof noteEnc.encryptedData.iv, 'string')
  t.is(typeof noteEnc.encryptedData.tag, 'string')
  t.is(noteEnc.title, undefined)
  t.is(noteEnc.body, undefined)

  const noteDec = await mod.decryptDoc(key, noteEnc)
  t.is(noteDec._id, note._id)
  t.is(noteDec.title, note.title)
  t.is(noteDec.body, note.body)
  t.is(noteDec.bookId, note.bookId)
})
