// @flow
import debug from 'debug'
const logger = {}

logger.debug = debug('inkdrop-encrypt:debug')
logger.info = debug('inkdrop-encrypt:info')
logger.error = debug('inkdrop-encrypt:error')

export default logger
