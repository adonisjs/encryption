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
import { EncryptionDriver } from '../encryption_driver.js'
import { Hmac } from '../hmac.js'
import type { EncryptionDriverContract, LegacyConfig } from '../types.js'

export class Legacy extends EncryptionDriver implements EncryptionDriverContract {
  constructor(config: LegacyConfig) {
    super(config)
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
  encrypt(payload: any, expiresIn?: string | number, purpose?: string) {
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = string.random(16)

    /**
     * Creating chiper
     */
    const cipher = createCipheriv('aes-256-cbc', this.cryptoKey, iv)

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

    /**
     * Returns the result + hmac
     */
    return `${result}${this.separator}${new Hmac(this.cryptoKey).generate(result)}`
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
     * [encrypted value].[iv].[hash]
     */
    const [encryptedEncoded, ivEncoded, hash] = value.split(this.separator)
    if (!encryptedEncoded || !ivEncoded || !hash) {
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
      const decipher = createDecipheriv('aes-256-cbc', this.cryptoKey, iv)
      const decrypted = decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8')
      return new MessageBuilder().verify(decrypted, purpose)
    } catch {
      return null
    }
  }

  /**
   * Returns a boolean telling if the value needs a re-encryption or not.
   * Legacy driver always returns true.
   */
  needsReEncrypt(_value: string): boolean {
    return true
  }
}
