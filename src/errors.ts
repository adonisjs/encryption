/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createError } from '@poppinss/utils'

export const E_INSECURE_APP_KEY = createError(
  'The value of "app.appKey" should be atleast 16 charcaters long',
  'E_INSECURE_APP_KEY'
)

export const E_MISSING_APP_KEY = createError(
  'Missing "app.appKey". The key is required to encrypt values',
  'E_MISSING_APP_KEY'
)
