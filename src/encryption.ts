/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import string from '@poppinss/utils/string'
import { base64, MessageBuilder } from '@poppinss/utils'
import { createHash, createCipheriv, createDecipheriv } from 'node:crypto'

import { Hmac } from './hmac.js'
import * as errors from './errors.js'
import type { EncryptionOptions } from './types.js'
import { MessageVerifier } from './message_verifier.js'

/**
 * The encryption class allows encrypting and decrypting values using `aes-256-cbc` or `aes-128-cbc`
 * algorithms. The encrypted value uses a unique iv for every encryption and this ensures semantic
 * security (read more https://en.wikipedia.org/wiki/Semantic_security).
 */
export class Encryption {
  #options: Required<EncryptionOptions>

  /**
   * The key for signing and encrypting values. It is derived
   * from the user provided secret.
   */
  #cryptoKey: Buffer

  /**
   * Use `dot` as a separator for joining encrypted value, iv and the
   * hmac hash. The idea is borrowed from JWTs.
   */
  #separator = '.'

  /**
   * Reference to the instance of message verifier for signing
   * and verifying values.
   */
  verifier: MessageVerifier

  /**
   * Reference to base64 object for base64 encoding/decoding values
   */
  base64: typeof base64 = base64

  /**
   * The algorithm in use
   */
  get algorithm(): 'aes-256-cbc' {
    return this.#options.algorithm
  }

  constructor(options: EncryptionOptions) {
    this.#options = { algorithm: 'aes-256-cbc', ...options }
    this.#validateSecret(options.secret)
    this.#cryptoKey = createHash('sha256').update(options.secret).digest()
    this.verifier = new MessageVerifier(options.secret)
  }

  /**
   * Validates the app secret
   */
  #validateSecret(secret?: string) {
    if (typeof secret !== 'string') {
      throw new errors.E_MISSING_APP_KEY()
    }

    if (secret.length < 16) {
      throw new errors.E_INSECURE_APP_KEY()
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
  encrypt(payload: any, expiresIn?: string | number, purpose?: string) {
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = string.random(16)

    /**
     * Creating chiper
     */
    const cipher = createCipheriv(this.algorithm, this.#cryptoKey, iv)

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
    const result = `${this.base64.urlEncode(encrypted)}${this.#separator}${this.base64.urlEncode(
      iv
    )}`

    /**
     * Returns the result + hmac
     */
    return `${result}${this.#separator}${new Hmac(this.#cryptoKey).generate(result)}`
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
    const [encryptedEncoded, ivEncoded, hash] = value.split(this.#separator)
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
    const isValidHmac = new Hmac(this.#cryptoKey).compare(
      `${encryptedEncoded}${this.#separator}${ivEncoded}`,
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
      const decipher = createDecipheriv(this.algorithm, this.#cryptoKey, iv)
      const decrypted = decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8')
      return new MessageBuilder().verify(decrypted, purpose)
    } catch {
      return null
    }
  }

  /**
   * Create a children instance with different secret key
   */
  child(options?: EncryptionOptions) {
    return new Encryption({ ...this.#options, ...options })
  }
}
