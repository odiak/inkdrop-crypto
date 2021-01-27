// @flow
import debug from 'debug'
const logger: {
  debug: Function,
  info: Function,
  error: Function
} = {
  debug: debug('inkdrop-crypto:debug'),
  info: debug('inkdrop-crypto:info'),
  error: debug('inkdrop-crypto:error')
}

export default logger
