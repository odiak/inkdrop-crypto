// @flow
import type { AesGcmCryptoModule, MD5Module } from './crypto-rn'
import CryptoBaseNode from './crypto-node'
import CryptoBaseRN from './crypto-rn'
import InkdropEncryption from './encryption'
export { InkdropEncryption }

export function createEncryptHelperForNode(): InkdropEncryption {
  const helper = new CryptoBaseNode(global.require('crypto'))
  return new InkdropEncryption(helper)
}

export function createEncryptHelperForRN(
  crypto: AesGcmCryptoModule,
  md5: MD5Module
): InkdropEncryption {
  const helper = new CryptoBaseRN(crypto, md5)
  return new InkdropEncryption(helper)
}

export function createEncryptHelperCustom(crypto: Object): InkdropEncryption {
  const helper = new CryptoBaseNode(crypto)
  return new InkdropEncryption(helper)
}

export type * from './crypto-rn'
export * from './types'
