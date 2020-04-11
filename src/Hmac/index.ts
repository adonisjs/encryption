/*
* @adonisjs/encryption
*
* (c) Harminder Virk <virk@adonisjs.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

import { createHmac } from 'crypto'
import { base64, safeEqual } from '@poppinss/utils'

/**
 * A generic class for generating SHA-256 Hmac for verifying the value
 * integrity.
 */
export class Hmac {
  constructor (private key: Buffer) {}

  /**
   * Generate the hmac
   */
  public generate (value: string) {
    return base64.urlEncode(createHmac('sha256', this.key).update(value).digest())
  }

  /**
   * Compare raw value against an existing hmac
   */
  public compare (value: string, existingHmac: string) {
    const newValueBuffer = Buffer.from(this.generate(value))

    /**
     * Allocate space as per the newHash length. This is required to avoid `safeEqual`
     * method from raising exceptions in case of length mis-match.
     *
     * Why there will be a length mis-match?
     * - The signed value was in correct format
     * - The encoded value was decoded
     * - However, the hash appended to the signed value was tampered and now has less
     *   characters than the original hash. The `safeEqual` method will raise exception
     *   if two buffers of different lengths are compared
     */
    const existingValueBuffer = Buffer.alloc(newValueBuffer.length)
    existingValueBuffer.write(existingHmac)
    return safeEqual(newValueBuffer, existingValueBuffer)
  }
}
