// @flow
import InkdropEncryption from './encryption'
export { InkdropEncryption }

export default function createEncryptHelper(crypto: Object): InkdropEncryption {
  return new InkdropEncryption(crypto)
}

export * from './types'
