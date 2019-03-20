import crypto from 'crypto'

export const algorithm = 'aes-256-gcm'

export function genKey(password, salt, iter = 90510) {
  if (typeof salt === 'string') {
    salt = Buffer.from(salt, 'hex')
  }
  const key = crypto.pbkdf2Sync(password, salt, iter, 256 / 8, 'sha512')
  return key.toString('base64').substring(0, 32)
}

export function createEncryptStream(key) {
  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String')
  }
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  return {
    algorithm,
    cipher,
    iv: iv.toString('hex')
  }
}

export function encrypt(key, data, opts) {
  const { outputEncoding, inputEncoding } = opts || {}
  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String')
  }
  const { algorithm: algo, cipher, iv } = createEncryptStream(key)
  let encrypted
  if (typeof data === 'string' || data instanceof Buffer) {
    encrypted = cipher.update(data, inputEncoding, outputEncoding)
  } else {
    throw new Error('Invalid data, it must be a String or Buffer')
  }
  if (encrypted instanceof Buffer) {
    encrypted = Buffer.concat([encrypted, cipher.final(outputEncoding)])
  } else {
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

export function createDecryptStream(key, meta) {
  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String')
  }
  if (typeof meta !== 'object') {
    throw new Error('Invalid meta, it must be a Object')
  }
  const { algorithm: algo, iv: ivStr, tag } = meta
  const iv = Buffer.from(ivStr, 'hex')
  const decipher = crypto.createDecipheriv(algo, key, iv)
  decipher.setAuthTag(Buffer.from(tag, 'hex'))
  return decipher
}

export function decrypt(key, data, opts) {
  const { inputEncoding, outputEncoding } = opts || {}
  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String')
  }
  if (typeof data !== 'object') {
    throw new Error('Invalid data, it must be a Object')
  }
  const decipher = createDecryptStream(key, data)
  let decrypted = decipher.update(data.content, inputEncoding, outputEncoding)
  if (decrypted instanceof Buffer) {
    decrypted = Buffer.concat([decrypted, decipher.final(outputEncoding)])
  } else {
    decrypted += decipher.final(outputEncoding)
  }
  return decrypted
}
