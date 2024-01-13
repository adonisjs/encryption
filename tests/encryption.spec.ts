/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Secret } from '@poppinss/utils'
import { Encryption } from '../src/encryption.js'

const SECRET = 'averylongradom32charactersstring'

test.group('Encryption | encrypt', () => {
  test('fail when secret is missing', ({ assert }) => {
    assert.throws(
      // @ts-expect-error
      () => new Encryption({ secret: null }),
      'Missing "app.appKey". The key is required to encrypt values'
    )
    assert.throws(
      // @ts-expect-error
      () => new Encryption({ secret: new Secret(null) }),
      'Missing "app.appKey". The key is required to encrypt values'
    )
  })

  test('fail when secret is not bigger than 16chars', ({ assert }) => {
    assert.throws(
      () => new Encryption({ secret: 'helloworld' }),
      'The value of "app.appKey" should be atleast 16 characters long'
    )

    assert.throws(
      () => new Encryption({ secret: new Secret('helloworld') }),
      'The value of "app.appKey" should be atleast 16 characters long'
    )
  })

  test('encrypt value', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    assert.notEqual(encryption.encrypt('hello-world'), 'hello-world')
    assert.equal(encryption.decrypt(encryption.encrypt('hello-world')), 'hello-world')
  })

  test('define encryption secret as a secret value', ({ assert }) => {
    const encryption = new Encryption({ secret: new Secret(SECRET) })
    assert.notEqual(encryption.encrypt('hello-world'), 'hello-world')
    assert.equal(encryption.decrypt(encryption.encrypt('hello-world')), 'hello-world')
  })

  test('encrypt an object', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.exists(encrypted)
  })

  test('ensure iv is random for each encryption call', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    assert.notEqual(
      encryption.encrypt({ username: 'virk' }),
      encryption.encrypt({ username: 'virk' })
    )
  })
})

test.group('Encryption | decrypt', () => {
  test('return null when decrypting non-string values', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    assert.isNull(encryption.decrypt(null))
  })

  test('decrypt encrypted value', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.deepEqual(encryption.decrypt(encrypted), { username: 'virk' })
  })

  test('define decryption secret as a secret value', ({ assert }) => {
    const encryption = new Encryption({ secret: new Secret(SECRET) })
    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.deepEqual(encryption.decrypt(encrypted), { username: 'virk' })
  })

  test('return null when value is in invalid format', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    assert.isNull(encryption.decrypt('foo'))
  })

  test('return null when unable to decode encrypted value', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    assert.isNull(encryption.decrypt('foo.bar.baz'))
  })

  test('return null when hash is tampered', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.isNull(encryption.decrypt(encrypted.slice(0, -2)))
  })

  test('return null when encrypted value is tampered', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.isNull(encryption.decrypt(encrypted.slice(2)))
  })

  test('return null when iv value is tampered', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' })

    const ivIndex = encrypted.indexOf('--') + 2
    const part1 = encrypted.slice(0, ivIndex)
    const part2 = encrypted.slice(ivIndex).slice(2)

    assert.isNull(encryption.decrypt(`${part1}${part2}`))
  })

  test('return null when purpose is missing during decrypt', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' }, undefined, 'login')
    assert.isNull(encryption.decrypt(encrypted))
  })

  test('return null when purpose is defined only during decrypt', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' })
    assert.isNull(encryption.decrypt(encrypted, 'login'))
  })

  test('return null when purpose are not same', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' }, undefined, 'register')
    assert.isNull(encryption.decrypt(encrypted, 'login'))
  })

  test('decrypt when purpose are same', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const encrypted = encryption.encrypt({ username: 'virk' }, undefined, 'register')
    assert.deepEqual(encryption.decrypt(encrypted, 'register'), { username: 'virk' })
  })

  test('get new instance of encryptor with different key', ({ assert }) => {
    const encryption = new Encryption({ secret: SECRET })
    const customEncryptor = encryption.child({ secret: 'another secret key' })
    assert.isNull(encryption.decrypt(customEncryptor.encrypt('hello-world')))
  })
})
