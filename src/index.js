// @flow
import CryptoBaseNode from './crypto-node'
import InkdropEncryption from './encryption'
export { InkdropEncryption }

export default function createEncryptHelperForNode(): InkdropEncryption {
  const helper = new CryptoBaseNode((require('crypto'): any))
  return new InkdropEncryption(helper)
}

export function createEncryptHelperCustom(crypto: Object): InkdropEncryption {
  const helper = new CryptoBaseNode(crypto)
  return new InkdropEncryption(helper)
}

export type * from './crypto-rn'
export * from './types'
