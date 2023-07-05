/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { RuntimeException } from '@poppinss/utils'

import debug from './debug.js'
import { Encryption } from './encryption.js'
import type { EncryptionDriverContract, ManagerDriverFactory } from './types.js'

export class EncryptionManager<KnownEncrypters extends Record<string, ManagerDriverFactory>>
  implements EncryptionDriverContract
{
  /**
   * Encryption manager config with the list of encrypters in
   * use
   */
  readonly #config: {
    default?: keyof KnownEncrypters
    list: KnownEncrypters
  }

  /**
   * Cache of encrypters
   */
  #encryptersCache: Partial<Record<keyof KnownEncrypters, Encryption>> = {}

  constructor(config: { default?: keyof KnownEncrypters; list: KnownEncrypters }) {
    this.#config = config
    debug('creating encryption manager. config: %O', this.#config)
  }

  /**
   * Creates an instance of a encryption driver
   */
  #createDriver<DriverFactory extends ManagerDriverFactory>(
    factory: DriverFactory
  ): ReturnType<DriverFactory> {
    return factory() as ReturnType<DriverFactory>
  }

  /**
   * Use one of the registered encrypters to encrypt values.
   *
   * ```ts
   * manager.use() // returns default encrypter
   * manager.use('aes_256_cbc')
   * ```
   */
  use<Encrypter extends keyof KnownEncrypters>(encrypter?: Encrypter): Encryption {
    let encrypterToUse: keyof KnownEncrypters | undefined = encrypter || this.#config.default

    if (!encrypterToUse) {
      throw new RuntimeException(
        'Cannot create encryption instance. No default encryption is defined in the config'
      )
    }

    /**
     * Use cached copy if exists
     */
    const cachedEncrypter = this.#encryptersCache[encrypterToUse]
    if (cachedEncrypter) {
      debug('using encrypter from cache. name: "%s"', encrypterToUse)
      return cachedEncrypter
    }

    const driverFactory = this.#config.list[encrypterToUse]

    /**
     * Create a new instance of Encryption class with the selected
     * driver and cache it
     */
    debug('creating encryption driver. name: "%s"', encrypterToUse)
    const encryption = new Encryption(this.#createDriver(driverFactory))
    this.#encryptersCache[encrypterToUse] = encryption
    return encryption
  }

  decrypt<T extends any>(value: string, purpose?: string): T | null {
    return this.use().decrypt(value, purpose)
  }

  encrypt(payload: any, expiresIn?: string | number, purpose?: string): string {
    return this.use().encrypt(payload, expiresIn, purpose)
  }

  needsReEncrypt(value: string): boolean {
    return this.use().needsReEncrypt(value)
  }
}
