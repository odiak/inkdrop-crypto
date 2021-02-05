// @flow
import type { CryptoBase } from './crypto'
import type CryptoModule from './module-crypto'
import type { EncryptedData } from './types'
import { EncryptError, DecryptError } from './types'
import type {
  PlainDataEncodingType,
  EncryptedDataEncodingType,
  CRYPTO_ALGORITHM
} from './types'

export const algorithm: CRYPTO_ALGORITHM = 'aes-256-gcm'

type EncryptionStream = {
  algorithm: CRYPTO_ALGORITHM,
  cipher: Object,
  iv: string
}

export default class CryptoBaseNode implements CryptoBase {
  crypto: CryptoModule
  constructor(crypto: CryptoModule) {
    this.crypto = crypto
  }

  genKey(password: string, salt: string | Buffer, iter: number): string {
    const { crypto } = this
    if (typeof salt === 'string') {
      salt = Buffer.from(salt, 'hex')
    }
    const key = crypto.pbkdf2Sync(password, salt, iter, 256 / 8, 'sha512')
    return key.toString('base64').substring(0, 32)
  }

  createEncryptStream(key: string): EncryptionStream {
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

  async encrypt(
    key: string,
    data: string | Buffer,
    opts?: {
      outputEncoding?: EncryptedDataEncodingType,
      inputEncoding?: PlainDataEncodingType
    }
  ): Promise<EncryptedData> {
    const { outputEncoding, inputEncoding } = opts || {}
    if (typeof key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    const { algorithm: algo, cipher, iv } = this.createEncryptStream(key)

    let encrypted
    if (typeof outputEncoding !== 'string') {
      if (typeof data === 'string' && inputEncoding) {
        encrypted = cipher.update(data, inputEncoding)
      } else if (data instanceof Buffer) {
        encrypted = cipher.update(data)
      } else {
        throw new EncryptError(
          'Encryption failed. Invalid data, it must be a String or Buffer'
        )
      }
      encrypted = Buffer.concat([encrypted, cipher.final(outputEncoding)])
    } else {
      if (typeof data === 'string' && inputEncoding) {
        encrypted = cipher.update(data, inputEncoding, outputEncoding)
      } else if (data instanceof Buffer) {
        encrypted = cipher.update(data, inputEncoding, outputEncoding)
      } else {
        throw new EncryptError(
          'Encryption failed. Invalid data, it must be a String or Buffer'
        )
      }
      encrypted += cipher.final(outputEncoding)
    }

    const tag = cipher.getAuthTag()
    return {
      algorithm: algo,
      content: encrypted,
      iv,
      tag: tag.toString('hex')
    }
  }

  createDecryptStream(key: string, meta: EncryptedData): Object {
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

  async decrypt(
    key: string,
    data: EncryptedData,
    opts: {
      outputEncoding?: PlainDataEncodingType,
      inputEncoding: EncryptedDataEncodingType
    }
  ): Promise<*> {
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
    } else if (data.content instanceof Buffer) {
      decrypted = decipher.update(data.content, undefined, outputEncoding)
    } else {
      throw new DecryptError(
        'Decryption failed. Invalid data, it must be a String or Buffer'
      )
    }

    if (decrypted instanceof Buffer && typeof outputEncoding !== 'string') {
      try {
        const final = decipher.final()
        return Buffer.concat([decrypted, final])
      } catch (e) {
        return decrypted
      }
    } else if (typeof decrypted === 'string' && outputEncoding) {
      try {
        const final = decipher.final(outputEncoding)
        return decrypted + final
      } catch (e) {
        return decrypted
      }
    } else {
      throw new DecryptError('Failed to decrypt. Invalid output encoding.')
    }
  }
}
