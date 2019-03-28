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

Use [rn-nodeify](https://github.com/tradle/rn-nodeify) for shimming crypto module in RN environment.

```
import './shim'
import createEncryptionHelper from 'inkdrop-crypto'
import crypto from 'crypto'

const helpers = createEncryptionHelper(crypto)
```

See [test](./test/index.js) to learn how to encrypt/decrypt data.
