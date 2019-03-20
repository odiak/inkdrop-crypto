Inkdrop Encryption Utilities
=============================

This module is for encrpting/decrypting user data in Inkdrop.

## How to use

### NodeJS

```
import { createEncryptionHelperWithNodeCrypto } from 'inkdrop-crypto'

const helpers = createEncryptionHelperWithNodeCrypto()
```

### React Native

Use [crypto-browserify](https://github.com/crypto-browserify/crypto-browserify) for shimming crypto module in RN environment.

```
import createEncryptionHelper from 'inkdrop-crypto'
import crypto from 'crypto-browserify'

const helpers = createEncryptionHelper(crypto)
```

See [test](./test/index.js) to learn how to encrypt/decrypt data.
