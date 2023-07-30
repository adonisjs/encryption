/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { ChaCha20Poly1305 } from '../../src/drivers/chacha20_poly1305.js'

const SECRET = 'averylongradom32charactersstring'

test.group('ChaCha20-Poly1305', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new ChaCha20Poly1305({ key: null }),
      'Missing key. The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16 chars', ({ assert }) => {
    assert.throws(
      () => new ChaCha20Poly1305({ id: 'lanz', key: 'helloworld' }),
      'The value of your key should be at least 16 characters long'
    )
  })

  test('fail when id is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new ChaCha20Poly1305({ key: SECRET }),
      'Missing id. The id is required to encrypt values'
    )
  })

  test('encrypt value', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    assert.notEqual(encryption.encrypt('hello-world'), 'hello-world')
  })

  test('encrypt an object with a secret', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    assert.notEqual(
      encryption.encrypt({ username: 'lanz' }),
      encryption.encrypt({ username: 'lanz' })
    )
  })

  test('return null when decrypting not the same id', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })

    assert.isNull(
      encryption.decrypt(
        'virk.chacha20poly1305.e84d46f8d04eba5de9ed218fde7711b7e04c16a71774f26f88baa44f2d7311.1ff0fbfc1141033d13e45384.03959acba4e476e68fc5dd0f2372b513.7z-DdSj1fndjvThpygKpWSpHUEHUf8IGw7Mey7k13Nw'
      )
    )
  })

  test('return null when decrypting not the same format', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })

    assert.isNull(
      encryption.decrypt(
        'lanz.chacha20poly1305.1ff0fbfc1141033d13e45384.03959acba4e476e68fc5dd0f2372b513.7z-DdSj1fndjvThpygKpWSpHUEHUf8IGw7Mey7k13Nw'
      )
    )
  })

  test('return null when decrypting not the same algo', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })

    assert.isNull(
      encryption.decrypt(
        'lanz.wrongalgo.1ff0fbfc1141033d13e45384.03959acba4e476e68fc5dd0f2372b513.7z-DdSj1fndjvThpygKpWSpHUEHUf8IGw7Mey7k13Nw'
      )
    )
  })

  test('return null when decrypting non-string values', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    // @ts-expect-error
    assert.isNull(encryption.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })

    assert.deepEqual(
      encryption.decrypt(
        'lanz.chacha20poly1305.e84d46f8d04eba5de9ed218fde7711b7e04c16a71774f26f88baa44f2d7311.1ff0fbfc1141033d13e45384.03959acba4e476e68fc5dd0f2372b513.7z-DdSj1fndjvThpygKpWSpHUEHUf8IGw7Mey7k13Nw'
      ),
      { username: 'lanz' }
    )
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    assert.isNull(encryption.decrypt('lanz.chacha20poly1305.foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    assert.isNull(encryption.decrypt('lanz.chacha20poly1305.foo.bar.baz'))
  })

  test('return null when hash is tampered', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted.slice(0, -2)))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(encryption.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' }, undefined, 'login')
    assert.isNull(encryption.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' })
    assert.isNull(encryption.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' }, undefined, 'register')
    assert.isNull(encryption.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const encryption = new ChaCha20Poly1305({ id: 'lanz', key: SECRET })
    const encrypted = encryption.encrypt({ username: 'lanz' }, undefined, 'register')
    assert.deepEqual(encryption.decrypt(encrypted, 'register'), { username: 'lanz' })
  })
})
