// @flow
import type { CryptoBase } from './crypto'
import type { EncryptedData } from './types'
import { EncryptError, DecryptError } from './types'
import type {
  PlainDataEncodingType,
  EncryptedDataEncodingType,
  CRYPTO_ALGORITHM
} from './types'

export const algorithm: CRYPTO_ALGORITHM = 'aes-256-gcm'

export type AesGcmEncryptedData = {
  iv: string,
  tag: string,
  content: string
}

export type AesGcmCryptoModule = {
  decrypt(
    base64Ciphertext: string,
    key: string,
    iv: string,
    tag: string,
    isBinary: boolean
  ): Promise<string>,
  encrypt(
    plainText: string,
    inBinary: boolean,
    key: string
  ): Promise<AesGcmEncryptedData>
}

export default class CryptoBaseRN implements CryptoBase {
  crypto: AesGcmCryptoModule
  constructor(crypto: AesGcmCryptoModule) {
    this.crypto = crypto
  }

  genKey(_password: string, _salt: string | Buffer, _iter: number): string {
    throw new Error('Not implemented')
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

    const isBinary = inputEncoding === 'binary' || data instanceof Buffer
    const plainData = data instanceof Buffer ? data.toString('base64') : data
    const sealed = await this.crypto.encrypt(plainData, isBinary, key)

    let encrypted
    if (typeof outputEncoding !== 'string') {
      encrypted = Buffer.from(sealed.content, 'base64')
    } else {
      if (
        (outputEncoding !== 'base64' && !isBinary) ||
        (outputEncoding === 'base64' && isBinary)
      ) {
        encrypted = sealed.content
      } else {
        const buf = Buffer.from(sealed.content, inputEncoding)
        encrypted =
          !outputEncoding || outputEncoding === 'binary'
            ? buf
            : buf.toString(outputEncoding)
      }
    }

    return {
      algorithm: algorithm,
      content: encrypted,
      iv: sealed.iv,
      tag: sealed.tag
    }
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
      throw new DecryptError('Invalid data, it must be an Object')
    }

    const isBinary = !outputEncoding || outputEncoding === 'binary'
    let ciphertext: string
    if (data.content instanceof Buffer) {
      ciphertext = data.content.toString('base64')
    } else if (inputEncoding) {
      ciphertext = Buffer.from(data, inputEncoding).toString('base64')
    } else {
      throw new DecryptError('Invalid data, it must be an Object')
    }
    const unsealed = await this.crypto.decrypt(
      ciphertext,
      key,
      data.iv,
      data.tag,
      isBinary
    )

    const decrypted = isBinary ? Buffer.from(unsealed, 'base64') : unsealed
    return decrypted
  }
}
