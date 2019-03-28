// @flow
import InkdropEncryption from './encryption'
export { InkdropEncryption }

export default function createEncryptHelper(crypto: Object) {
  return new InkdropEncryption(crypto)
}

export * from './types'
