/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { ManagerDriverFactory } from '../src/types.js'
import { Legacy } from '../src/drivers/legacy.js'
import { EncryptionManager } from '../src/encryption_manager.js'

type Config<KnownEncrypters extends Record<string, ManagerDriverFactory>> = {
  default?: keyof KnownEncrypters
  list: KnownEncrypters
}

export class EncryptionManagerFactory<
  KnownEncrypters extends Record<string, ManagerDriverFactory> = { legacy: () => Legacy }
> {
  /**
   * Config accepted by encryption manager
   */
  #config: Config<KnownEncrypters>

  constructor(config?: { default?: keyof KnownEncrypters; list: KnownEncrypters }) {
    this.#config =
      config ||
      ({
        default: 'legacy',
        list: {
          legacy: () => new Legacy({ key: 'averylongrandomsecretkey' }),
        },
      } as unknown as Config<KnownEncrypters>)
  }

  /**
   * Merge factory parameters
   */
  merge<Encrypters extends Record<string, ManagerDriverFactory>>(
    config: Config<Encrypters>
  ): EncryptionManagerFactory<Encrypters> {
    return new EncryptionManagerFactory(config)
  }

  /**
   * Create hash manager instance
   */
  create() {
    return new EncryptionManager<KnownEncrypters>(this.#config)
  }
}
