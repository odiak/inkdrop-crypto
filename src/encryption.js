// @flow
import logger from './logger'
import pick from 'lodash.pick'
import { EncryptError, DecryptError } from './types'
import CryptoBase from './crypto'
import type { EncryptionKey } from './types'

const fieldsToEncrypt = ['title', 'body', 'name']

export default class InkdropEncryption extends CryptoBase {
  /**
   * @returns {object} The masked encryption key
   */
  maskEncryptionKey(
    password: string,
    salt: string,
    encryptionKey: string | Buffer
  ): EncryptionKey {
    const key = this.genKey(password, salt, 128)
    return {
      salt,
      ...this.encrypt(key, encryptionKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    }
  }

  /**
   * @returns {object} The masked encryption key
   */
  createEncryptionKey(password: string): EncryptionKey {
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
    encryptionKeyData: EncryptionKey
  ): string {
    if (typeof password !== 'string') {
      throw new DecryptError('The new password must be a string')
    }
    if (typeof encryptionKeyData !== 'object') {
      throw new DecryptError('The encryption key data must be an object')
    }
    const { salt } = encryptionKeyData
    const key = this.genKey(password, salt, 128)
    const revealedKey = this.decrypt(key, encryptionKeyData, {
      inputEncoding: 'base64',
      outputEncoding: 'utf8'
    })
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
    encryptionKeyData: EncryptionKey
  ) {
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
    if (!doc || typeof doc.body !== 'string') {
      throw new EncryptError('The doccument must have body field to encrypt')
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
    // backward compatibility
    if (doc.encrypted) {
      logger.info(
        "The note can't be decrypted because it's encrypted with the client app. Skip decrypting."
      )
      return doc
    }
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
}
