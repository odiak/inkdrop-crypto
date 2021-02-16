// @flow
import logger from './logger'
import pick from 'lodash.pick'
import base64 from 'base64-js'
import { EncryptError, DecryptError } from './types'
import type { CryptoBase } from './crypto'
import type { MaskedEncryptionKey } from './types'

const fieldsToEncrypt = ['title', 'body', 'name']

export default class InkdropEncryption {
  helper: CryptoBase

  constructor(helper: CryptoBase) {
    this.helper = helper
  }

  /**
   * Note: NoteJS only
   * @returns {object} The masked encryption key
   */
  async maskEncryptionKey(
    password: string,
    salt: string,
    iter: number,
    encryptionKey: string | Buffer
  ): Promise<MaskedEncryptionKey> {
    const key = await this.helper.deriveKey(password, salt, iter)
    const data: Object = {
      ...(await this.helper.encrypt(key, encryptionKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })),
      salt,
      iterations: iter
    }
    return data
  }

  /**
   * Note: NoteJS only
   * @returns {object} The masked encryption key
   */
  async createEncryptionKey(
    password: string,
    iter: number
  ): Promise<MaskedEncryptionKey> {
    const crypto = global.require('crypto')
    if (typeof password !== 'string') {
      throw new EncryptError('The password must be a string')
    }
    if (typeof iter !== 'number') {
      throw new EncryptError('The iteration must be a number')
    }
    const salt = crypto.randomBytes(16).toString('hex')
    const key = crypto.randomBytes(32).toString('base64').substring(0, 32)
    return this.maskEncryptionKey(password, salt, iter, key)
  }

  /**
   * @returns {string} The encryption key
   */
  async revealEncryptionKey(
    password: string,
    encryptionKeyData: MaskedEncryptionKey
  ): Promise<string> {
    if (typeof password !== 'string') {
      throw new DecryptError('The new password must be a string')
    }
    if (typeof encryptionKeyData !== 'object') {
      throw new DecryptError('The encryption key data must be an object')
    }
    const { salt, iterations } = encryptionKeyData
    const key = await this.helper.deriveKey(password, salt, iterations)
    const revealedKey = await this.helper.decrypt(
      key,
      { ...encryptionKeyData },
      {
        inputEncoding: 'base64',
        outputEncoding: 'utf8'
      }
    )
    if (typeof revealedKey === 'string') {
      return revealedKey
    } else {
      throw new DecryptError('Invalid encryption key')
    }
  }

  /**
   * Note: NoteJS only
   * @returns {object} The masked encryption key
   */
  async updateEncryptionKey(
    oldPassword: string,
    password: string,
    iter: number,
    encryptionKeyData: MaskedEncryptionKey
  ): Promise<MaskedEncryptionKey> {
    if (typeof oldPassword !== 'string') {
      throw new DecryptError('The old password must be a string')
    }
    if (typeof password !== 'string') {
      throw new EncryptError('The new password must be a string')
    }
    if (typeof iter !== 'number') {
      throw new EncryptError('The iteration must be a number')
    }
    if (typeof encryptionKeyData !== 'object') {
      throw new DecryptError('The encryption key data must be an object')
    }
    if (typeof encryptionKeyData.salt !== 'string') {
      throw new DecryptError('The encryption key data does not have salt')
    }
    const key = await this.revealEncryptionKey(oldPassword, encryptionKeyData)
    return this.maskEncryptionKey(password, encryptionKeyData.salt, iter, key)
  }

  async encryptDoc(key: string, doc: Object): Promise<Object> {
    if (doc.encryptedData) {
      // The note is already encrypted with the client app. Skip encrypting.
      return doc
    }
    if (typeof key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    if (!doc) {
      throw new DecryptError('The document must be specified')
    }
    const data = JSON.stringify(pick(doc, fieldsToEncrypt))
    const encryptedData = await this.helper.encrypt(key, data, {
      inputEncoding: 'utf8',
      outputEncoding: 'base64'
    })
    doc.encryptedData = encryptedData
    fieldsToEncrypt.forEach(field => delete doc[field])

    return doc
  }

  async decryptDoc(key: string, doc: Object): Promise<Object> {
    if (!key) {
      throw new DecryptError('The encryption key must be specified')
    }
    if (!doc) {
      throw new DecryptError('The document must be specified')
    }
    if (!doc.encryptedData) {
      logger.info('The note is not encrypted. Skip decrypting.')
      return doc
    }
    const strJson = await this.helper.decrypt(key, doc.encryptedData, {
      inputEncoding: 'base64',
      outputEncoding: 'utf8'
    })
    if (typeof strJson === 'string') {
      Object.assign(doc, JSON.parse(strJson))
    } else {
      throw new DecryptError('Invalid decrypted data')
    }
    delete doc.encryptedData

    return doc
  }

  async encryptFile(key: string, doc: Object): Promise<Object> {
    if (typeof key !== 'string') {
      throw new EncryptError('Invalid key. it must be a String')
    }
    if (doc && doc._id.startsWith('file:')) {
      if (doc.encryptionData) {
        // The note is already encrypted with the client app. Skip encrypting.
        return doc
      }
      if (doc._attachments && doc._attachments.index) {
        const { index: att } = doc._attachments
        let data = null
        if (att.data instanceof Buffer) {
          data = att.data
        } else if (typeof att.data === 'string') {
          data = Buffer.from(att.data, 'base64')
        } else {
          throw new EncryptError('Invalid data type')
        }
        const encryptedData = await this.helper.encrypt(key, data, {
          inputEncoding: 'binary',
          outputEncoding: 'base64'
        })
        if (typeof encryptedData.content === 'string') {
          const md5digest = this.helper.calcMD5Hash(
            encryptedData.content,
            'base64'
          )
          doc._attachments.index = {
            content_type: `application/${encryptedData.algorithm}-encrypted`,
            data: encryptedData.content,
            length: base64.byteLength(encryptedData.content),
            digest: 'md5-' + md5digest
          }
          doc.encryptionData = pick(encryptedData, ['algorithm', 'iv', 'tag'])
          doc.contentLength = data.length
          if (!doc.md5digest) {
            doc.md5digest = this.helper.calcMD5Hash(att.data, 'hex')
          }
        }
        return doc
      } else {
        throw new EncryptError('Invalid file document')
      }
    } else {
      throw new EncryptError('Invalid document. It must be a file doc.')
    }
  }

  async decryptFile(key: string, doc: Object): Promise<Object> {
    if (!key) {
      throw new DecryptError('The encryption key must be specified')
    }
    if (!doc) {
      throw new DecryptError('The document must be specified')
    }
    if (!doc.encryptionData) {
      logger.info('The file is not encrypted. Skip decrypting.')
      return doc
    }
    if (doc && doc._id.startsWith('file:')) {
      if (doc._attachments && doc._attachments.index) {
        const { index: att } = doc._attachments
        let data = null
        if (att.data instanceof Buffer) {
          data = att.data
        } else if (typeof att.data === 'string') {
          data = Buffer.from(att.data, 'base64')
        } else {
          throw new DecryptError('Invalid data type')
        }
        const encryptedContent = {
          ...doc.encryptionData,
          content: data
        }
        const decryptedContent = await this.helper.decrypt(
          key,
          encryptedContent,
          {
            inputEncoding: 'binary',
            outputEncoding: 'base64'
          }
        )
        const md5digest = this.helper.calcMD5Hash(decryptedContent, 'base64')
        doc._attachments.index = {
          data: decryptedContent,
          length: doc.contentLength,
          content_type: doc.contentType,
          digest: 'md5-' + md5digest
        }
        delete doc.encryptionData
        return doc
      } else {
        throw new DecryptError('Invalid file document')
      }
    } else {
      throw new DecryptError('Invalid document. It must be a file doc.')
    }
  }
}
