/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createCipheriv, createDecipheriv } from 'node:crypto'
import string from '@poppinss/utils/string'
import { MessageBuilder } from '@poppinss/utils'
import * as errors from '../exceptions.js'
import { BaseDriver } from './base_driver.js'
import { Hmac } from '../hmac.js'
import type { AES256GCMConfig, EncryptionDriverContract } from '../types.js'

export class AES256GCM extends BaseDriver implements EncryptionDriverContract {
  #config: AES256GCMConfig

  constructor(config: AES256GCMConfig) {
    super(config)

    this.#config = config

    if (typeof config.id !== 'string') {
      throw new errors.E_MISSING_ENCRYPTER_ID()
    }
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
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = string.random(16)

    /**
     * Creating chiper
     */
    const cipher = createCipheriv('aes-256-gcm', this.cryptoKey, iv)

    /**
     * Encoding value to a string so that we can set it on the cipher
     */
    const encodedValue = new MessageBuilder().build(payload, expiresIn, purpose)

    /**
     * Set final to the cipher instance and encrypt it
     */
    const encrypted = Buffer.concat([cipher.update(encodedValue, 'utf-8'), cipher.final()])

    /**
     * Concatenate `encrypted value` and `iv` by urlEncoding them. The concatenation is required
     * to generate the HMAC, so that HMAC checks for integrity of both the `encrypted value`
     * and the `iv`.
     */
    const result = `${this.base64.urlEncode(encrypted)}${this.separator}${this.base64.urlEncode(
      iv
    )}`

    const nounce = cipher.getAuthTag().toString('hex')

    /**
     * Returns the result + hmac
     */
    return `${this.#config.id}${this.separator}aes256gcm${this.separator}${result}${
      this.separator
    }${nounce}${this.separator}${new Hmac(this.cryptoKey).generate(result)}`
  }

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null {
    if (typeof value !== 'string') {
      return null
    }

    /**
     * Make sure the encrypted value is in correct format. ie
     * [id].[algo].[encrypted value].[iv].[nounce].[hash]
     */
    const [id, algo, encryptedEncoded, ivEncoded, nounceEncoded, hash] = value.split(this.separator)
    if (!id || !algo || !encryptedEncoded || !ivEncoded || !nounceEncoded || !hash) {
      return null
    }

    /**
     * Make sure the algo is correct
     */
    if (algo !== 'aes256gcm') {
      return null
    }

    /**
     * Make sure the id is correct
     */
    if (id !== this.#config.id) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the encrypted value
     */
    const encrypted = this.base64.urlDecode(encryptedEncoded, 'base64')
    if (!encrypted) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the iv
     */
    const iv = this.base64.urlDecode(ivEncoded)
    if (!iv) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the nounce
     */
    const nounce = Buffer.from(nounceEncoded, 'hex')
    if (!nounce) {
      return null
    }

    /**
     * Make sure the hash is correct, it means the first 2 parts of the
     * string are not tampered.
     */
    const isValidHmac = new Hmac(this.cryptoKey).compare(
      `${encryptedEncoded}${this.separator}${ivEncoded}`,
      hash
    )

    if (!isValidHmac) {
      return null
    }

    /**
     * The Decipher can raise exceptions with malformed input, so we wrap it
     * to avoid leaking sensitive information
     */
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.cryptoKey, iv)
      decipher.setAuthTag(nounce)
      const decrypted = decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8')
      return new MessageBuilder().verify(decrypted, purpose)
    } catch {
      return null
    }
  }
}
