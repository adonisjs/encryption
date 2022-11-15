/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'

export class InsecureAppKeyException extends Exception {
  static status = 500
  static code = 'E_INSECURE_APP_KEY'
  static message = 'The value of "app.appKey" should be atleast 16 charcaters long'
}
