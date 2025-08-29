/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createHmac } from 'node:crypto'
import { safeEqual } from '@poppinss/utils'
import base64 from '@poppinss/utils/base64'

/**
 * A generic class for generating SHA-256 Hmac for verifying the value
 * integrity.
 */
export class Hmac {
  /**
   * The cryptographic key used for HMAC generation
   */
  #key: Buffer

  /**
   * Creates a new HMAC instance with the provided cryptographic key
   *
   * @param key - The buffer containing the cryptographic key
   */
  constructor(key: Buffer) {
    this.#key = key
  }

  /**
   * Generate the hmac
   *
   * @param value - The string value to generate HMAC for
   * @returns The base64 URL encoded HMAC hash
   */
  generate(value: string): string {
    return base64.urlEncode(createHmac('sha256', this.#key).update(value).digest('hex'))
  }

  /**
   * Compare raw value against an existing hmac
   *
   * @param value - The original string value
   * @param existingHmac - The existing HMAC to compare against
   * @returns True if the HMACs match, false otherwise
   */
  compare(value: string, existingHmac: string): boolean {
    return safeEqual(this.generate(value), existingHmac)
  }
}
