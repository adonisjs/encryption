/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Encryption } from '../src/encryption.js'
import { EncryptionManager } from '../src/encryption_manager.js'
import { Legacy } from '../src/drivers/legacy.js'

const SECRET = 'averylongradom32charactersstring'

test.group('Encryption manager', () => {
  test('create encryption instance from the manager', ({ assert, expectTypeOf }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ key: SECRET }),
      },
    })

    expectTypeOf(manager.use).parameter(0).toEqualTypeOf<'legacy' | undefined>()

    expectTypeOf(manager.use('legacy')).toEqualTypeOf<Encryption>()

    assert.instanceOf(manager.use('legacy'), Encryption)
  })

  test('cache encryption instance', ({ assert, expectTypeOf }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ key: SECRET }),
        legacy1: () => new Legacy({ key: SECRET }),
      },
    })

    expectTypeOf(manager.use).parameter(0).toEqualTypeOf<'legacy' | 'legacy1' | undefined>()

    expectTypeOf(manager.use('legacy')).toEqualTypeOf<Encryption>()
    expectTypeOf(manager.use('legacy1')).toEqualTypeOf<Encryption>()

    assert.strictEqual(manager.use('legacy'), manager.use('legacy'))
    assert.notStrictEqual(manager.use('legacy'), manager.use('legacy1'))
  })

  test('use default encryption driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ key: SECRET }),
      },
    })

    assert.strictEqual(manager.use(), manager.use('legacy'))
  })

  test('fail when default encrypter is not configured', ({ assert }) => {
    const manager = new EncryptionManager({
      list: {
        legacy: () => new Legacy({ key: SECRET }),
      },
    })

    assert.throws(
      () => manager.use(),
      'Cannot create encryption instance. No default encryption is defined in the config'
    )
  })

  test('encrypt text using the default driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ key: SECRET }),
      },
    })

    const encrypted = manager.encrypt('hello world')
    assert.notEqual(encrypted, 'hello world')
  })

  test('decrypt text using the default driver', ({ assert }) => {
    const manager = new EncryptionManager({
      default: 'legacy',
      list: {
        legacy: () => new Legacy({ key: SECRET }),
      },
    })

    const encrypted = manager.encrypt('hello world')
    assert.deepEqual(manager.decrypt(encrypted), 'hello world')
  })
})
