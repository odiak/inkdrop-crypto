// @flow
import type { AesGcmCryptoModule, MD5Module, PBKDF2Module } from './crypto-rn'
import CryptoBaseRN from './crypto-rn'
import InkdropEncryption from './encryption'
export { InkdropEncryption }

export default function createEncryptHelperForRN(
  crypto: AesGcmCryptoModule,
  md5: MD5Module,
  pbkdf2: PBKDF2Module
): InkdropEncryption {
  if (!crypto) throw new Error('AesGcmCryptoModule is required')
  if (!md5) throw new Error('MD5Module is required')
  if (!pbkdf2) throw new Error('PBKDF2Module is required')
  const helper = new CryptoBaseRN(crypto, md5, pbkdf2)
  return new InkdropEncryption(helper)
}

export type * from './crypto-rn'
export * from './types'
