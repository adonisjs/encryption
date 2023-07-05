/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { EncryptionDriverContract } from './types.js'

export class Encryption implements EncryptionDriverContract {
  #driver: EncryptionDriverContract

  constructor(driver: EncryptionDriverContract) {
    this.#driver = driver
  }

  /**
   * Encrypt a given piece of value using the app secret. A wide range of
   * data types are supported.
   *
   * - String
   * - Arrays
   * - Objects
   * - Booleans
   * - Numbers
   * - Dates
   *
   * You can optionally define a purpose for which the value was encrypted and
   * mentioning a different purpose/no purpose during decrypt will fail.
   */
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): string {
    return this.#driver.encrypt(payload, expiresIn, purpose)
  }

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null {
    return this.#driver.decrypt(value, purpose)
  }

  /**
   * Returns a boolean telling if the value needs a re-encryption or not.
   */
  needsReEncrypt(value: string): boolean {
    return this.#driver.needsReEncrypt(value)
  }
}
