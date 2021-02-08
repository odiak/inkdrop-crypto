// @flow
import {
  createEncryptHelperForRN,
  createEncryptHelperForNode,
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
    base64Key: string,
    ivStr: string,
    tag: string,
    isBinary: boolean
  ): Promise<string> {
    if (typeof base64Key !== 'string') {
      throw new DecryptError('Invalid key. it must be a String')
    }
    const key = Buffer.from(base64Key, 'base64').toString('utf8')
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
    base64Key: string
  ): Promise<AesGcmEncryptedData> {
    if (typeof base64Key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    const key = Buffer.from(base64Key, 'base64').toString('utf8')
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
    return crypto
      .createHash('md5')
      .update(Buffer.from(content, 'base64'))
      .digest(outputEncoding)
  }
}

const pbkdf2Mock = {
  hash(
    password: ArrayBuffer | string,
    salt: ArrayBuffer | string,
    iterations: number,
    keyLength: number
  ): Promise<ArrayBuffer> {
    const bufPassword =
      password instanceof ArrayBuffer
        ? Buffer.from(password)
        : Buffer.from(password, 'utf8')
    const bufSalt =
      salt instanceof ArrayBuffer
        ? Buffer.from(salt)
        : Buffer.from(salt, 'utf8')
    const key = crypto.pbkdf2Sync(
      bufPassword,
      bufSalt,
      iterations,
      keyLength,
      'sha512'
    )
    return Promise.resolve(key.buffer)
  }
}

test('check exports', t => {
  t.is(typeof createEncryptHelperForRN, 'function')
})

test('mock', async t => {
  const modNode = createEncryptHelperForNode()
  const modRN = createEncryptHelperForRN(cryptoMock, md5Mock, pbkdf2Mock)
  const salt = '5ea40cea861387bb39fba0faacb9b54e'

  const keyRN = await modRN.helper.deriveKey('foo', salt, 1000)
  const keyNode = await modNode.helper.deriveKey('foo', salt, 1000)
  t.log('derived key:', keyRN)
  t.is(keyRN, keyNode)

  const md5RN = modRN.helper.calcMD5Hash('Zm9v', 'hex')
  const md5Node = modNode.helper.calcMD5Hash('Zm9v', 'hex')
  t.is(md5RN, md5Node)

  const key = 'ei+hoOW4Bk8xQGADwMax9N55hbT7gj7P'
  const sealedRN = await modRN.helper.encrypt(key, 'data', {
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  })
  t.log('sealedRN:', sealedRN)
  const sealedNode = await modNode.helper.encrypt(key, 'data', {
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  })
  const unsealedRN = await modRN.helper.decrypt(key, sealedNode, {
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  const unsealedNode = await modRN.helper.decrypt(key, sealedRN, {
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.deepEqual(unsealedRN, unsealedNode)
})

test('revealing encryption key', async t => {
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock, pbkdf2Mock)
  const keyMasked = {
    algorithm: 'aes-256-gcm',
    content: '1zjc6kUCnVFvpY7DRcC8eGD9nO1+pZJtXuTnKPniAuo=',
    iterations: 100000,
    iv: '9103be37426183bc7327323b',
    salt: 'ea5564336fa562aed21bbcd8ae178464',
    tag: '227ab98553d5051eaf50de151c075487'
  }
  const keyUnmasked = await mod.revealEncryptionKey('foo', keyMasked)
  t.is(keyUnmasked, '/AnN2+oCb1X7/GAzV5IQLHxLqT+9Milv')
})

test('generating encryption key', async t => {
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock, pbkdf2Mock)
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
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock, pbkdf2Mock)
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
  const mod = createEncryptHelperForRN(cryptoMock, md5Mock, pbkdf2Mock)
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
