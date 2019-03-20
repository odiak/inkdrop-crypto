// @flow
import type { EncryptedData } from './types'
import { EncryptError, DecryptError } from './types'
import type { PlainDataEncodingType, EncryptedDataEncodingType } from './types'

export const algorithm = 'aes-256-gcm'

export default class CryptoBase {
  crypto: CryptoModule
  constructor(crypto: CryptoModule) {
    this.crypto = crypto
  }

  genKey(password: string, salt: string | Buffer, iter: number = 90510) {
    const { crypto } = this
    if (typeof salt === 'string') {
      salt = Buffer.from(salt, 'hex')
    }
    const key = crypto.pbkdf2Sync(password, salt, iter, 256 / 8, 'sha512')
    return key.toString('base64').substring(0, 32)
  }

  createEncryptStream(key: string) {
    const { crypto } = this
    if (typeof key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv(algorithm, key, iv)
    return {
      algorithm,
      cipher,
      iv: iv.toString('hex')
    }
  }

  encrypt(
    key: string,
    data: string | Buffer,
    opts?: {
      outputEncoding?: EncryptedDataEncodingType,
      inputEncoding?: PlainDataEncodingType
    }
  ): EncryptedData {
    const { outputEncoding, inputEncoding } = opts || {}
    if (typeof key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    const { algorithm: algo, cipher, iv } = this.createEncryptStream(key)
    let encrypted
    if (typeof data === 'string' && inputEncoding) {
      encrypted = cipher.update(data, inputEncoding, outputEncoding)
    } else if (data instanceof Buffer && outputEncoding) {
      encrypted = cipher.update(data, inputEncoding, outputEncoding)
    } else {
      throw new EncryptError(
        'Encryption failed. Invalid data, it must be a String or Buffer'
      )
    }
    if (encrypted instanceof Buffer && !outputEncoding) {
      encrypted = Buffer.concat([encrypted, cipher.final(outputEncoding)])
    } else if (typeof encrypted === 'string' && outputEncoding) {
      encrypted += cipher.final(outputEncoding)
    } else {
      throw new EncryptError('Encryption failed. Invalid output encoding.')
    }
    const tag = cipher.getAuthTag()
    return {
      algorithm: algo,
      content: encrypted,
      iv,
      tag: tag.toString('hex')
    }
  }

  createDecryptStream(key: string, meta: EncryptedData) {
    const { crypto } = this
    if (typeof key !== 'string') {
      throw new DecryptError('Invalid key. it must be a String')
    }
    if (typeof meta !== 'object') {
      throw new DecryptError('Invalid meta, it must be a Object')
    }
    const { algorithm: algo, iv: ivStr, tag } = meta
    const iv = Buffer.from(ivStr, 'hex')
    const decipher = crypto.createDecipheriv(algo, key, iv)
    decipher.setAuthTag(Buffer.from(tag, 'hex'))
    return decipher
  }

  decrypt(
    key: string,
    data: EncryptedData,
    opts: {
      outputEncoding?: PlainDataEncodingType,
      inputEncoding: EncryptedDataEncodingType
    }
  ) {
    const { inputEncoding, outputEncoding } = opts || {}
    if (typeof key !== 'string') {
      throw new DecryptError('Invalid key. it must be a String')
    }
    if (typeof data !== 'object') {
      throw new DecryptError('Invalid data, it must be a Object')
    }
    const decipher = this.createDecryptStream(key, data)
    let decrypted
    if (typeof data.content === 'string' && inputEncoding) {
      decrypted = decipher.update(data.content, inputEncoding, outputEncoding)
    } else if (data.content instanceof Buffer && outputEncoding) {
      decrypted = decipher.update(data.content, undefined, outputEncoding)
    } else {
      throw new DecryptError(
        'Decryption failed. Invalid data, it must be a String or Buffer'
      )
    }

    if (decrypted instanceof Buffer && typeof outputEncoding !== 'string') {
      return Buffer.concat([decrypted, decipher.final()])
    } else if (typeof decrypted === 'string' && outputEncoding) {
      decrypted += decipher.final(outputEncoding)
      return decrypted
    } else {
      throw new DecryptError('Failed to decrypt. Invalid output encoding.')
    }
  }
}