/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Legacy } from '../../src/drivers/legacy.js'
import { AES256GCM } from '../../src/drivers/aes_256_gcm.js'

const SECRET = 'averylongradom32charactersstring'

test.group('AES-256-GCM', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256GCM({ key: null }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new AES256GCM({ id: 'lanz', key: 'helloworld' }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('fail when id is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new AES256GCM({ key: SECRET }),
      'Missing id. The id is required to encrypt values'
    )
  })

  test('encrypt value', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    assert.notEqual(encryption.encrypt('hello-world'), 'hello-world')
    assert.equal(encryption.decrypt(encryption.encrypt('hello-world')), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    assert.notEqual(
      encryption.encrypt({ username: 'lanz' }),
      encryption.encrypt({ username: 'lanz' })
    )
  })

  test('return null when decrypting not the same id', ({ assert }) => {
    const encryption1 = new AES256GCM({ id: 'lanz', key: SECRET })
    const encryption2 = new AES256GCM({ id: 'virk', key: SECRET })

    const encrypted = encryption1.encrypt({ username: 'lanz' })
    assert.isNull(encryption2.decrypt(encrypted))
  })

  test('return null when decrypting not the same algo', ({ assert }) => {
    const legacy = new Legacy({ key: SECRET })
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })

    const encrypted = legacy.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted))
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    // @ts-expect-error
    assert.isNull(encryption.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.deepEqual(encryption.decrypt(encrypted), { username: 'lanz' })
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    assert.isNull(encryption.decrypt('foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    assert.isNull(encryption.decrypt('foo.bar.baz'))
  })

  test('return null when hash is tampered', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted.slice(0, -2)))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(encryption.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' }, undefined, 'login')
    assert.isNull(encryption.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' }, undefined, 'register')
    assert.isNull(encryption.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const encryption = new AES256GCM({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' }, undefined, 'register')
    assert.deepEqual(encryption.decrypt(encrypted, 'register'), { username: 'lanz' })
  })
})