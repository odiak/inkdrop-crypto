// @flow
import type { EncryptedData } from './types'
import type {
  PlainDataEncodingType,
  EncryptedDataEncodingType,
  CRYPTO_ALGORITHM
} from './types'

export interface CryptoBase {
  genKey(password: string, salt: string | Buffer, iter: number): string;
  encrypt(
    key: string,
    data: string | Buffer,
    opts?: {
      outputEncoding?: EncryptedDataEncodingType,
      inputEncoding?: PlainDataEncodingType
    }
  ): Promise<EncryptedData>;
  decrypt(
    key: string,
    data: EncryptedData,
    opts: {
      outputEncoding?: PlainDataEncodingType,
      inputEncoding: EncryptedDataEncodingType
    }
  ): Promise<*>;
}
