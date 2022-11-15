/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'

export class MissingAppKeyException extends Exception {
  static status = 500
  static code = 'E_MISSING_APP_KEY'
  static message = 'Missing "app.appKey". The key is required to encrypt values'
}
