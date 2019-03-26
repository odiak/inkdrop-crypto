// @flow
import InkdropEncryption from './encryption'

export default function createEncryptHelper(crypto: CryptoModule) {
  return new InkdropEncryption(crypto)
}

export function createEncryptionHelperWithNodeCrypto() {
  const crypto = require('crypto')
  return new InkdropEncryption((crypto: any))
}

export * from './types'
