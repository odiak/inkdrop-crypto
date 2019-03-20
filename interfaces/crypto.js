// @flow

type crypto$createCredentialsDetails = any // TODO

declare class crypto$Cipher extends stream$Duplex {
  final(output_encoding: 'latin1' | 'binary' | 'base64' | 'hex'): string;
  final(output_encoding: void): Buffer;
  getAuthTag(): Buffer;
  setAAD(buffer: Buffer): crypto$Cipher;
  setAuthTag(buffer: Buffer): void;
  setAutoPadding(auto_padding?: boolean): crypto$Cipher;
  update(
    data: string,
    input_encoding: 'utf8' | 'ascii' | 'latin1' | 'binary',
    output_encoding: 'latin1' | 'binary' | 'base64' | 'hex'
  ): string;
  update(
    data: string,
    input_encoding: 'utf8' | 'ascii' | 'latin1' | 'binary',
    output_encoding: void
  ): Buffer;
  update(
    data: Buffer,
    input_encoding: void | 'utf8' | 'ascii' | 'latin1' | 'binary',
    output_encoding: 'latin1' | 'binary' | 'base64' | 'hex'
  ): string;
  update(data: Buffer, input_encoding: void, output_encoding: void): Buffer;
}

type crypto$Credentials = {
  // TODO
}

type crypto$DiffieHellman = {
  computeSecret(
    other_public_key: string,
    input_encoding?: string,
    output_encoding?: string
  ): any,
  generateKeys(encoding?: string): any,
  getGenerator(encoding?: string): any,
  getPrime(encoding?: string): any,
  getPrivateKey(encoding?: string): any,
  getPublicKey(encoding?: string): any,
  setPrivateKey(private_key: any, encoding?: string): void,
  setPublicKey(public_key: any, encoding?: string): void
}

type crypto$ECDH$Encoding = 'latin1' | 'hex' | 'base64'
type crypto$ECDH$Format = 'compressed' | 'uncompressed'

declare class crypto$ECDH {
  computeSecret(other_public_key: Buffer | $TypedArray | DataView): Buffer;
  computeSecret(
    other_public_key: string,
    input_encoding: crypto$ECDH$Encoding
  ): Buffer;
  computeSecret(
    other_public_key: Buffer | $TypedArray | DataView,
    output_encoding: crypto$ECDH$Encoding
  ): string;
  computeSecret(
    other_public_key: string,
    input_encoding: crypto$ECDH$Encoding,
    output_encoding: crypto$ECDH$Encoding
  ): string;
  generateKeys(format?: crypto$ECDH$Format): Buffer;
  generateKeys(
    encoding: crypto$ECDH$Encoding,
    format?: crypto$ECDH$Format
  ): string;
  getPrivateKey(): Buffer;
  getPrivateKey(encoding: crypto$ECDH$Encoding): string;
  getPublicKey(format?: crypto$ECDH$Format): Buffer;
  getPublicKey(
    encoding: crypto$ECDH$Encoding,
    format?: crypto$ECDH$Format
  ): string;
  setPrivateKey(private_key: Buffer | $TypedArray | DataView): void;
  setPrivateKey(private_key: string, encoding: crypto$ECDH$Encoding): void;
}

declare class crypto$Decipher extends stream$Duplex {
  final(output_encoding: 'latin1' | 'binary' | 'ascii' | 'utf8'): string;
  final(output_encoding: void): Buffer;
  getAuthTag(): Buffer;
  setAAD(buffer: Buffer): void;
  setAuthTag(buffer: Buffer): void;
  setAutoPadding(auto_padding?: boolean): crypto$Cipher;
  update(
    data: string,
    input_encoding: 'latin1' | 'binary' | 'base64' | 'hex',
    output_encoding: 'latin1' | 'binary' | 'ascii' | 'utf8'
  ): string;
  update(
    data: string,
    input_encoding: 'latin1' | 'binary' | 'base64' | 'hex',
    output_encoding: void
  ): Buffer;
  update(
    data: Buffer,
    input_encoding: void,
    output_encoding: 'latin1' | 'binary' | 'ascii' | 'utf8'
  ): string;
  update(data: Buffer, input_encoding: void, output_encoding: void): Buffer;
}

declare class crypto$Hash extends stream$Duplex {
  digest(encoding: 'hex' | 'latin1' | 'binary' | 'base64'): string;
  digest(encoding: 'buffer'): Buffer;
  digest(encoding: void): Buffer;
  update(
    data: string | Buffer,
    input_encoding?: 'utf8' | 'ascii' | 'latin1' | 'binary'
  ): crypto$Hash;
}

declare class crypto$Hmac extends stream$Duplex {
  digest(encoding: 'hex' | 'latin1' | 'binary' | 'base64'): string;
  digest(encoding: 'buffer'): Buffer;
  digest(encoding: void): Buffer;
  update(
    data: string | Buffer,
    input_encoding?: 'utf8' | 'ascii' | 'latin1' | 'binary'
  ): crypto$Hmac;
}

type crypto$Sign$private_key =
  | string
  | {
      key: string,
      passphrase: string
    }
declare class crypto$Sign extends stream$Writable {
  static (algorithm: string, options?: writableStreamOptions): crypto$Sign;
  constructor(algorithm: string, options?: writableStreamOptions): void;
  sign(
    private_key: crypto$Sign$private_key,
    output_format: 'latin1' | 'binary' | 'hex' | 'base64'
  ): string;
  sign(private_key: crypto$Sign$private_key, output_format: void): Buffer;
  update(
    data: string | Buffer,
    input_encoding?: 'utf8' | 'ascii' | 'latin1' | 'binary'
  ): crypto$Sign;
}

declare class crypto$Verify extends stream$Writable {
  static (algorithm: string, options?: writableStreamOptions): crypto$Verify;
  constructor(algorithm: string, options?: writableStreamOptions): void;
  update(
    data: string | Buffer,
    input_encoding?: 'utf8' | 'ascii' | 'latin1' | 'binary'
  ): crypto$Verify;
  verify(
    object: string,
    signature: string | Buffer | $TypedArray | DataView,
    signature_format: 'latin1' | 'binary' | 'hex' | 'base64'
  ): boolean;
  verify(object: string, signature: Buffer, signature_format: void): boolean;
}

type crypto$key =
  | string
  | {
      key: string,
      passphrase?: string,
      padding?: string // TODO: enum type in crypto.constants
    }

declare class CryptoModule {
  Sign: crypto$Sign;
  Verify: crypto$Verify;

  createCipher(algorithm: string, password: string | Buffer): crypto$Cipher;
  createCipheriv(
    algorithm: string,
    key: string | Buffer,
    iv: string | Buffer
  ): crypto$Cipher;
  createCredentials(
    details?: crypto$createCredentialsDetails
  ): crypto$Credentials;
  createDecipher(algorithm: string, password: string | Buffer): crypto$Decipher;
  createDecipheriv(
    algorithm: string,
    key: string | Buffer,
    iv: string | Buffer
  ): crypto$Decipher;
  createDiffieHellman(prime_length: number): crypto$DiffieHellman;
  createDiffieHellman(prime: number, encoding?: string): crypto$DiffieHellman;
  createECDH(curveName: string): crypto$ECDH;
  createHash(algorithm: string): crypto$Hash;
  createHmac(algorithm: string, key: string | Buffer): crypto$Hmac;
  createSign(algorithm: string): crypto$Sign;
  createVerify(algorithm: string): crypto$Verify;
  getCiphers(): Array<string>;
  getCurves(): Array<string>;
  getDiffieHellman(group_name: string): crypto$DiffieHellman;
  getHashes(): Array<string>;
  pbkdf2(
    password: string | Buffer,
    salt: string | Buffer,
    iterations: number,
    keylen: number,
    digestOrCallback: string | ((err: ?Error, derivedKey: Buffer) => void),
    callback?: (err: ?Error, derivedKey: Buffer) => void
  ): void;
  pbkdf2Sync(
    password: string | Buffer,
    salt: string | Buffer,
    iterations: number,
    keylen: number,
    digest?: string
  ): Buffer;
  privateDecrypt(private_key: crypto$key, buffer: Buffer): Buffer;
  privateEncrypt(private_key: crypto$key, buffer: Buffer): Buffer;
  publicDecrypt(key: crypto$key, buffer: Buffer): Buffer;
  publicEncrypt(key: crypto$key, buffer: Buffer): Buffer;
  // `UNUSED` argument strictly enforces arity to enable overloading this
  // function with 1-arg and 2-arg variants.
  pseudoRandomBytes(size: number, UNUSED: void): Buffer;
  pseudoRandomBytes(
    size: number,
    callback: (err: ?Error, buffer: Buffer) => void
  ): void;
  // `UNUSED` argument strictly enforces arity to enable overloading this
  // function with 1-arg and 2-arg variants.
  randomBytes(size: number, UNUSED: void): Buffer;
  randomBytes(
    size: number,
    callback: (err: ?Error, buffer: Buffer) => void
  ): void;
  randomFillSync(buffer: Buffer): void;
  randomFillSync(buffer: Buffer, offset: number): void;
  randomFillSync(buffer: Buffer, offset: number, size: number): void;
  randomFill(
    buffer: Buffer,
    callback: (err: ?Error, buffer: Buffer) => void
  ): void;
  randomFill(
    buffer: Buffer,
    offset: number,
    callback: (err: ?Error, buffer: Buffer) => void
  ): void;
  randomFill(
    buffer: Buffer,
    offset: number,
    size: number,
    callback: (err: ?Error, buffer: Buffer) => void
  ): void;
  timingSafeEqual(
    a: Buffer | $TypedArray | DataView,
    b: Buffer | $TypedArray | DataView
  ): boolean;
}
