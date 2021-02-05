// @flow
import type { AesGcmCryptoModule } from './crypto-rn'
import CryptoBaseNode from './crypto-node'
import CryptoBaseRN from './crypto-rn'
import InkdropEncryption from './encryption'
export { InkdropEncryption }

export function createEncryptHelperForNode(): InkdropEncryption {
  const helper = new CryptoBaseNode(global.require('crypto'))
  return new InkdropEncryption(helper)
}

export function createEncryptHelperForRN(
  crypto: AesGcmCryptoModule
): InkdropEncryption {
  const helper = new CryptoBaseRN(crypto)
  return new InkdropEncryption(helper)
}

export function createEncryptHelperCustom(crypto: Object): InkdropEncryption {
  const helper = new CryptoBaseNode(crypto)
  return new InkdropEncryption(helper)
}

export * from './types'
