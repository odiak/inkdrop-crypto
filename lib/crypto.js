'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.algorithm = undefined;

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

exports.genKey = genKey;
exports.createEncryptStream = createEncryptStream;
exports.encrypt = encrypt;
exports.createDecryptStream = createDecryptStream;
exports.decrypt = decrypt;

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var algorithm = exports.algorithm = 'aes-256-gcm';

function genKey(password, salt) {
  var iter = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 90510;

  if (typeof salt === 'string') {
    salt = Buffer.from(salt, 'hex');
  }
  var key = _crypto2.default.pbkdf2Sync(password, salt, iter, 256 / 8, 'sha512');
  return key.toString('base64').substring(0, 32);
}

function createEncryptStream(key) {
  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String');
  }
  var iv = _crypto2.default.randomBytes(12);
  var cipher = _crypto2.default.createCipheriv(algorithm, key, iv);
  return {
    algorithm: algorithm,
    cipher: cipher,
    iv: iv.toString('hex')
  };
}

function encrypt(key, data, opts) {
  var _ref = opts || {},
      outputEncoding = _ref.outputEncoding,
      inputEncoding = _ref.inputEncoding;

  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String');
  }

  var _createEncryptStream = createEncryptStream(key),
      algo = _createEncryptStream.algorithm,
      cipher = _createEncryptStream.cipher,
      iv = _createEncryptStream.iv;

  var encrypted = void 0;
  if (typeof data === 'string' || data instanceof Buffer) {
    encrypted = cipher.update(data, inputEncoding, outputEncoding);
  } else {
    throw new Error('Invalid data, it must be a String or Buffer');
  }
  if (encrypted instanceof Buffer) {
    encrypted = Buffer.concat([encrypted, cipher.final(outputEncoding)]);
  } else {
    encrypted += cipher.final(outputEncoding);
  }
  var tag = cipher.getAuthTag();
  return {
    algorithm: algo,
    content: encrypted,
    iv: iv,
    tag: tag.toString('hex')
  };
}

function createDecryptStream(key, meta) {
  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String');
  }
  if ((typeof meta === 'undefined' ? 'undefined' : _typeof(meta)) !== 'object') {
    throw new Error('Invalid meta, it must be a Object');
  }
  var algo = meta.algorithm,
      ivStr = meta.iv,
      tag = meta.tag;

  var iv = Buffer.from(ivStr, 'hex');
  var decipher = _crypto2.default.createDecipheriv(algo, key, iv);
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return decipher;
}

function decrypt(key, data, opts) {
  var _ref2 = opts || {},
      inputEncoding = _ref2.inputEncoding,
      outputEncoding = _ref2.outputEncoding;

  if (typeof key !== 'string') {
    throw new Error('Invalid key. it must be a String');
  }
  if ((typeof data === 'undefined' ? 'undefined' : _typeof(data)) !== 'object') {
    throw new Error('Invalid data, it must be a Object');
  }
  var decipher = createDecryptStream(key, data);
  var decrypted = decipher.update(data.content, inputEncoding, outputEncoding);
  if (decrypted instanceof Buffer) {
    decrypted = Buffer.concat([decrypted, decipher.final(outputEncoding)]);
  } else {
    decrypted += decipher.final(outputEncoding);
  }
  return decrypted;
}