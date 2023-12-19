/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { type Secret } from '@poppinss/utils'

/**
 * Config accepted by the encryption
 */
export type EncryptionOptions = {
  algorithm?: 'aes-256-cbc'
  secret: string | Secret<string>
}
