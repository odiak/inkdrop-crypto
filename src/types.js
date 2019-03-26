// @flow

export type EncryptionMetadata = {
  algorithm: string,
  iv: string,
  tag: string
}

export type EncryptedData = EncryptionMetadata & {
  content: string | Buffer
}

export type MaskedEncryptionKey = EncryptedData & {
  salt: string
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

export type PlainDataEncodingType = 'utf8' | 'ascii' | 'latin1' | 'binary'
export type EncryptedDataEncodingType = 'latin1' | 'binary' | 'base64' | 'hex'
