'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.maskEncryptionKey = maskEncryptionKey;
exports.createEncryptionKey = createEncryptionKey;
exports.revealEncryptionKey = revealEncryptionKey;
exports.updateEncryptionKey = updateEncryptionKey;
exports.encryptNote = encryptNote;
exports.decryptNote = decryptNote;

var _logger = require('./logger');

var _logger2 = _interopRequireDefault(_logger);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _lodash = require('lodash.pick');

var _lodash2 = _interopRequireDefault(_lodash);

var _crypto3 = require('./crypto');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var DecryptError = function (_Error) {
  _inherits(DecryptError, _Error);

  function DecryptError(message) {
    _classCallCheck(this, DecryptError);

    var _this = _possibleConstructorReturn(this, (DecryptError.__proto__ || Object.getPrototypeOf(DecryptError)).call(this, message));

    _this.name = 'DecryptError';
    return _this;
  }

  return DecryptError;
}(Error);

var EncryptError = function (_Error2) {
  _inherits(EncryptError, _Error2);

  function EncryptError(message) {
    _classCallCheck(this, EncryptError);

    var _this2 = _possibleConstructorReturn(this, (EncryptError.__proto__ || Object.getPrototypeOf(EncryptError)).call(this, message));

    _this2.name = 'EncryptError';
    return _this2;
  }

  return EncryptError;
}(Error);

/**
 * @returns {object} The masked encryption key
 */


function maskEncryptionKey(password, salt, encryptionKey) {
  var key = (0, _crypto3.genKey)(password, salt, 128);
  return _extends({
    salt: salt
  }, (0, _crypto3.encrypt)(key, encryptionKey, { inputEncoding: 'utf8', outputEncoding: 'base64' }));
}

/**
 * @returns {object} The masked encryption key
 */
function createEncryptionKey(password) {
  if (typeof password !== 'string') {
    throw new Error('The new password must be a string');
  }
  var salt = _crypto2.default.randomBytes(16).toString('hex');
  var key = _crypto2.default.randomBytes(16).toString('hex');
  return maskEncryptionKey(password, salt, key);
}

/**
 * @returns {string} The encryption key
 */
function revealEncryptionKey(password, encryptionKeyData) {
  if (typeof password !== 'string') {
    throw new Error('The new password must be a string');
  }
  if ((typeof encryptionKeyData === 'undefined' ? 'undefined' : _typeof(encryptionKeyData)) !== 'object') {
    throw new Error('The encryption key data must be an object');
  }
  var salt = encryptionKeyData.salt;

  var key = (0, _crypto3.genKey)(password, salt, 128);
  return (0, _crypto3.decrypt)(key, encryptionKeyData, { inputEncoding: 'base64', outputEncoding: 'utf8' });
}

/**
 * @returns {object} The masked encryption key
 */
function updateEncryptionKey(oldPassword, password, encryptionKeyData) {
  if (typeof oldPassword !== 'string') {
    throw new Error('The old password must be a string');
  }
  if (typeof password !== 'string') {
    throw new Error('The new password must be a string');
  }
  if ((typeof encryptionKeyData === 'undefined' ? 'undefined' : _typeof(encryptionKeyData)) !== 'object') {
    throw new Error('The encryption key data must be an object');
  }
  if (typeof encryptionKeyData.salt !== 'string') {
    throw new Error('The encryption key data does not have salt');
  }
  var key = revealEncryptionKey(oldPassword, encryptionKeyData);
  return maskEncryptionKey(password, encryptionKeyData.salt, key);
}

function encryptNote(key, doc) {
  // backward compatibility
  if (doc.encrypted) {
    _logger2.default.info('The note is already encrypted with the client app. Skip encrypting.');
    return doc;
  }
  if (!key) {
    throw new EncryptError('The encryption key must be specified');
  }
  if (!doc || typeof doc.body !== 'string') {
    throw new EncryptError('The doccument must have body field to encrypt');
  }
  var data = JSON.stringify((0, _lodash2.default)(doc, 'title', 'body'));
  var encryptedData = (0, _crypto3.encrypt)(key, data, { inputEncoding: 'utf8', outputEncoding: 'base64' });
  doc.encryptedData = encryptedData;
  delete doc.body;
  delete doc.title;

  return doc;
}

function decryptNote(key, doc) {
  // backward compatibility
  if (doc.encrypted) {
    _logger2.default.info('The note can\'t be decrypted because it\'s encrypted with the client app. Skip decrypting.');
    return doc;
  }
  if (!key) {
    throw new DecryptError('The encryption key must be specified');
  }
  if (!doc) {
    throw new DecryptError('The document must be specified');
  }
  if (!doc.encryptedData) {
    _logger2.default.info('The note is not encrypted. Skip decrypting.');
    return doc;
  }
  var strJson = (0, _crypto3.decrypt)(key, doc.encryptedData, { inputEncoding: 'base64', outputEncoding: 'utf8' });
  Object.assign(doc, JSON.parse(strJson));
  delete doc.encryptedData;

  return doc;
}