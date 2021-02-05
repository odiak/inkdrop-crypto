// @flow
export type CRYPTO_ALGORITHM = 'aes-256-gcm'

export type EncryptionMetadata = {
  algorithm: CRYPTO_ALGORITHM,
  iv: string,
  tag: string
}

export type EncryptedData = EncryptionMetadata & {
  content: string | Buffer
}

export type MaskedEncryptionKey = {
  algorithm: CRYPTO_ALGORITHM,
  iv: string,
  tag: string,
  salt: string,
  iterations: number,
  content: string
}

export class DecryptError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DecryptError'
  }
}

export class EncryptError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EncryptError'
  }
}

export type PlainDataEncodingType =
  | 'utf8'
  | 'ascii'
  | 'latin1'
  | 'binary'
  | 'base64'
export type EncryptedDataEncodingType = 'latin1' | 'binary' | 'base64' | 'hex'
