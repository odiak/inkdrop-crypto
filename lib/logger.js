'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _debug = require('debug');

var _debug2 = _interopRequireDefault(_debug);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var logger = {};

logger.debug = (0, _debug2.default)('inkdrop-encrypt:debug');
logger.info = (0, _debug2.default)('inkdrop-encrypt:info');
logger.error = (0, _debug2.default)('inkdrop-encrypt:error');

exports.default = logger;