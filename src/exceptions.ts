/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createError } from '@poppinss/utils'

export const E_INSECURE_ENCRYPTER_KEY = createError(
  'The value of your key should be at least 16 characters long',
  'E_INSECURE_ENCRYPTER_KEY'
)

export const E_MISSING_ENCRYPTER_KEY = createError(
  'Missing key. The key is required to encrypt values',
  'E_MISSING_ENCRYPTER_KEY'
)
