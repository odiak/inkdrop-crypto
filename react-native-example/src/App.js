// @flow
import * as React from 'react'

import { StyleSheet, View, Text } from 'react-native'
import * as InkdropCrypto from 'inkdrop-crypto'
import AesGcmCrypto from 'react-native-aes-gcm-crypto'
import Md5 from 'react-native-quick-md5'
import SimpleCrypto from 'react-native-simple-crypto'

console.log('InkdropCrypto:', InkdropCrypto)
console.log('AesGcmCrypto:', AesGcmCrypto)
console.log('Md5:', Md5)
console.log('SimpleCrypto:', SimpleCrypto.PBKDF2)
const mod = InkdropCrypto.createEncryptHelperForRN(
  AesGcmCrypto,
  Md5,
  SimpleCrypto.PBKDF2
)
console.log('crypto:', mod)

export default function App() {
  const [result, setResult] = React.useState<?string>()

  React.useEffect(() => {
    const doIt = async () => {
      try {
        const salt = '5ea40cea861387bb39fba0faacb9b54e'
        const keyRN = await mod.helper.deriveKey('foo', salt, 1000)
        console.log('keyRN:', keyRN)

        const key = 'ei+hoOW4Bk8xQGADwMax9N55hbT7gj7P'
        const sealedRN = await mod.helper.encrypt(key, 'data', {
          inputEncoding: 'utf8',
          outputEncoding: 'base64'
        })
        console.log('sealedRN:', JSON.stringify(sealedRN, null, 4))
        const unsealedRN = await mod.helper.decrypt(key, sealedRN, {
          inputEncoding: 'base64',
          outputEncoding: 'utf8'
        })
        console.log('unsealedRN:', unsealedRN)
        const unsealedRN2 = await mod.helper.decrypt(
          key,
          {
            algorithm: 'aes-256-gcm',
            content: 'hGW2Gg==',
            iv: 'f7a7248faea07ea9cd44c351',
            tag: '44295290263eb1daa66e6009d1c527cd'
          },
          {
            inputEncoding: 'base64',
            outputEncoding: 'utf8'
          }
        )
        console.log('unsealedRN2:', unsealedRN2)
        if (unsealedRN2 !== 'data') console.error('Failed to decrypt data')

        const keyMasked = {
          algorithm: 'aes-256-gcm',
          content: '1zjc6kUCnVFvpY7DRcC8eGD9nO1+pZJtXuTnKPniAuo=',
          iterations: 100000,
          iv: '9103be37426183bc7327323b',
          salt: 'ea5564336fa562aed21bbcd8ae178464',
          tag: '227ab98553d5051eaf50de151c075487'
        }
        const keyUnmasked = await mod.revealEncryptionKey('foo', keyMasked)
        setResult(JSON.stringify(keyUnmasked, null, 4))
        console.log('keyUnmasked:', keyUnmasked)
        if (keyUnmasked !== '/AnN2+oCb1X7/GAzV5IQLHxLqT+9Milv')
          console.error('Failed to reveal the key')

        const note = {
          _id: 'note:test',
          title: 'title',
          body: '# This is markdown',
          bookId: 'book:test',
          tags: [],
          createdAt: +new Date(),
          updatedAt: +new Date()
        }
        const noteEnc = await mod.encryptDoc(key, note)
        console.log('encrypted note:', noteEnc)
        const noteDec = await mod.decryptDoc(key, noteEnc)
        console.log('decrypted note:', noteDec)
      } catch (e) {
        console.error(e)
      }
    }
    doIt()
  }, [])

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center'
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20
  }
})
