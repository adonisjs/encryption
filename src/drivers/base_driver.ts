/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createHash } from 'node:crypto'
import { base64 } from '@poppinss/utils'
import * as errors from '../exceptions.js'
import { MessageVerifier } from '../message_verifier.js'
import type { BaseConfig } from '../types.js'

export abstract class BaseDriver {
  /**
   * The key for signing and encrypting values. It is derived
   * from the user provided secret.
   */
  cryptoKey: Buffer

  /**
   * Use `dot` as a separator for joining encrypted value, iv and the
   * hmac hash. The idea is borrowed from JWTs.
   */
  separator = '.'

  /**
   * Reference to the instance of message verifier for signing
   * and verifying values.
   */
  verifier: MessageVerifier

  /**
   * Reference to base64 object for base64 encoding/decoding values
   */
  base64: typeof base64 = base64

  protected constructor(config: BaseConfig) {
    this.#validateSecret(config.key)
    this.cryptoKey = createHash('sha256').update(config.key).digest()
    this.verifier = new MessageVerifier(config.key)
  }

  /**
   * Validates the app secret
   */
  #validateSecret(secret?: string) {
    if (typeof secret !== 'string') {
      throw new errors.E_MISSING_ENCRYPTER_KEY()
    }

    if (secret.length < 16) {
      throw new errors.E_INSECURE_ENCRYPTER_KEY()
    }
  }

  computeReturns(values: string[]) {
    return values.join(this.separator)
  }

  /**
   * Returns the message verifier instance
   */
  getMessageVerifier() {
    return this.verifier
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
  abstract encrypt(payload: any, expiresIn?: string | number, purpose?: string): string

  /**
   * Decrypt value and verify it against a purpose
   */
  abstract decrypt<T extends any>(value: string, purpose?: string): T | null
}
