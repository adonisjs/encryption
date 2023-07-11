/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * The contract Encryption drivers should adhere to
 */
export interface EncryptionDriverContract {
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
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): string

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null
}

/**
 * Factory function to return the driver implementation. The method
 * cannot be async, because the API that calls this method is not
 * async in first place.
 */
export type ManagerDriverFactory = () => EncryptionDriverContract

export interface BaseConfig {
  key: string
}

export interface LegacyConfig extends BaseConfig {}

export type Config<KnownEncrypters extends Record<string, ManagerDriverFactory>> = {
  default?: keyof KnownEncrypters
  list: KnownEncrypters
}
