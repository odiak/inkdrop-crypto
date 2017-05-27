import logger from './logger'
import crypto from 'crypto'
import pick from 'lodash.pick'
import { genKey, encrypt, decrypt } from './crypto'

class DecryptError extends Error {
  constructor (message) {
    super(message)
    this.name = 'DecryptError'
  }
}

class EncryptError extends Error {
  constructor (message) {
    super(message)
    this.name = 'EncryptError'
  }
}

/**
 * @returns {object} The masked encryption key
 */
export function maskEncryptionKey (password, salt, encryptionKey) {
  const key = genKey(password, salt, 128)
  return {
    salt,
    ...encrypt(key, encryptionKey, { inputEncoding: 'utf8', outputEncoding: 'base64' })
  }
}

/**
 * @returns {object} The masked encryption key
 */
export function createEncryptionKey (password) {
  if (typeof password !== 'string') {
    throw new Error('The new password must be a string')
  }
  const salt = crypto.randomBytes(16).toString('hex')
  const key = crypto.randomBytes(16).toString('hex')
  return maskEncryptionKey(password, salt, key)
}

/**
 * @returns {string} The encryption key
 */
export function revealEncryptionKey (password, encryptionKeyData) {
  if (typeof password !== 'string') {
    throw new Error('The new password must be a string')
  }
  if (typeof encryptionKeyData !== 'object') {
    throw new Error('The encryption key data must be an object')
  }
  const { salt } = encryptionKeyData
  const key = genKey(password, salt, 128)
  return decrypt(key, encryptionKeyData, { inputEncoding: 'base64', outputEncoding: 'utf8' })
}

/**
 * @returns {object} The masked encryption key
 */
export function updateEncryptionKey (oldPassword, password, encryptionKeyData) {
  if (typeof oldPassword !== 'string') {
    throw new Error('The old password must be a string')
  }
  if (typeof password !== 'string') {
    throw new Error('The new password must be a string')
  }
  if (typeof encryptionKeyData !== 'object') {
    throw new Error('The encryption key data must be an object')
  }
  if (typeof encryptionKeyData.salt !== 'string') {
    throw new Error('The encryption key data does not have salt')
  }
  const key = revealEncryptionKey(oldPassword, encryptionKeyData)
  return maskEncryptionKey(password, encryptionKeyData.salt, key)
}

export function encryptNote (key, doc) {
  // backward compatibility
  if (doc.encrypted) {
    logger.info('The note is already encrypted with the client app. Skip encrypting.')
    return doc
  }
  if (!key) {
    throw new EncryptError('The encryption key must be specified')
  }
  if (!doc || typeof doc.body !== 'string') {
    throw new EncryptError('The doccument must have body field to encrypt')
  }
  const data = JSON.stringify(pick(doc, 'title', 'body'))
  const encryptedData = encrypt(key, data, { inputEncoding: 'utf8', outputEncoding: 'base64' })
  doc.encryptedData = encryptedData
  delete doc.body
  delete doc.title

  return doc
}

export function decryptNote (key, doc) {
  // backward compatibility
  if (doc.encrypted) {
    logger.info('The note can\'t be decrypted because it\'s encrypted with the client app. Skip decrypting.')
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
  const strJson = decrypt(key, doc.encryptedData, { inputEncoding: 'base64', outputEncoding: 'utf8' })
  Object.assign(doc, JSON.parse(strJson))
  delete doc.encryptedData

  return doc
}
