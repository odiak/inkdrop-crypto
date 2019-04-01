// @flow
import logger from './logger'
import pick from 'lodash.pick'
import { EncryptError, DecryptError } from './types'
import CryptoBase from './crypto'
import type { MaskedEncryptionKey } from './types'

const fieldsToEncrypt = ['title', 'body', 'name']

export default class InkdropEncryption extends CryptoBase {
  /**
   * @returns {object} The masked encryption key
   */
  maskEncryptionKey(
    password: string,
    salt: string,
    encryptionKey: string | Buffer
  ): MaskedEncryptionKey {
    const key = this.genKey(password, salt, 128)
    const data: Object = {
      ...this.encrypt(key, encryptionKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      }),
      salt
    }
    return data
  }

  /**
   * @returns {object} The masked encryption key
   */
  createEncryptionKey(password: string): MaskedEncryptionKey {
    const { crypto } = this
    if (typeof password !== 'string') {
      throw new EncryptError('The new password must be a string')
    }
    const salt = crypto.randomBytes(16).toString('hex')
    const key = crypto.randomBytes(16).toString('hex')
    return this.maskEncryptionKey(password, salt, key)
  }

  /**
   * @returns {string} The encryption key
   */
  revealEncryptionKey(
    password: string,
    encryptionKeyData: MaskedEncryptionKey
  ): string {
    if (typeof password !== 'string') {
      throw new DecryptError('The new password must be a string')
    }
    if (typeof encryptionKeyData !== 'object') {
      throw new DecryptError('The encryption key data must be an object')
    }
    const { salt } = encryptionKeyData
    const key = this.genKey(password, salt, 128)
    const revealedKey = this.decrypt(
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
   * @returns {object} The masked encryption key
   */
  updateEncryptionKey(
    oldPassword: string,
    password: string,
    encryptionKeyData: MaskedEncryptionKey
  ): MaskedEncryptionKey {
    if (typeof oldPassword !== 'string') {
      throw new DecryptError('The old password must be a string')
    }
    if (typeof password !== 'string') {
      throw new EncryptError('The new password must be a string')
    }
    if (typeof encryptionKeyData !== 'object') {
      throw new DecryptError('The encryption key data must be an object')
    }
    if (typeof encryptionKeyData.salt !== 'string') {
      throw new DecryptError('The encryption key data does not have salt')
    }
    const key = this.revealEncryptionKey(oldPassword, encryptionKeyData)
    return this.maskEncryptionKey(password, encryptionKeyData.salt, key)
  }

  encryptDoc(key: string, doc: Object) {
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
    const encryptedData = this.encrypt(key, data, {
      inputEncoding: 'utf8',
      outputEncoding: 'base64'
    })
    doc.encryptedData = encryptedData
    fieldsToEncrypt.forEach(field => delete doc[field])

    return doc
  }

  decryptDoc(key: string, doc: Object) {
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
    const strJson = this.decrypt(key, doc.encryptedData, {
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

  encryptFile(key: string, doc: Object) {
    const { crypto } = this
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
        const encryptedData = this.encrypt(key, data, {
          inputEncoding: 'binary',
          outputEncoding: 'base64'
        })
        if (typeof encryptedData.content === 'string') {
          const encryptedBuffer = Buffer.from(encryptedData.content, 'base64')
          const md5digest = crypto
            .createHash('md5')
            .update(encryptedBuffer)
            .digest('base64')
          doc._attachments.index = {
            content_type: `application/${encryptedData.algorithm}-encrypted`,
            data: encryptedData.content,
            length: encryptedBuffer.length,
            digest: 'md5-' + md5digest
          }
          doc.encryptionData = pick(encryptedData, ['algorithm', 'iv', 'tag'])
          doc.contentLength = data.length
          if (!doc.md5digest) {
            doc.md5digest = crypto
              .createHash('md5')
              .update(data)
              .digest('hex')
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

  decryptFile(key: string, doc: Object) {
    const { crypto } = this
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
        const decryptedContent = this.decrypt(key, encryptedContent, {
          inputEncoding: 'binary'
        })
        const decryptedData = decryptedContent.toString('base64')
        const md5digest = crypto
          .createHash('md5')
          .update(decryptedContent)
          .digest('base64')
        doc._attachments.index = {
          data: decryptedData,
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
