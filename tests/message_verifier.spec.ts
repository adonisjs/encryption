/*
 * @adonisjs/encryption
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { base64 } from '@poppinss/utils'
import { MessageVerifier } from '../src/message_verifier.js'

const SECRET = 'averylongradom32charactersstring'

test.group('Message Verifier', () => {
  test('disallow signing null and undefined values', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    assert.throws(() => encryption.sign(null), 'Cannot sign "null" value')
    assert.throws(() => encryption.sign(undefined), 'Cannot sign "undefined" value')
  })

  test('sign an object using a secret', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    const signed = encryption.sign({ username: 'virk' })
    assert.equal(base64.urlDecode(signed.split('.')[0]), '{"message":{"username":"virk"}}')
  })

  test('sign an object with purpose', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    const signed = encryption.sign({ username: 'virk' }, undefined, 'login')
    assert.equal(
      base64.urlDecode(signed.split('.')[0]),
      '{"message":{"username":"virk"},"purpose":"login"}'
    )
  })

  test('return null when unsigning non-string values', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    // @ts-expect-error
    assert.isNull(encryption.unsign({}))
    // @ts-expect-error
    assert.isNull(encryption.unsign(null))
    // @ts-expect-error
    assert.isNull(encryption.unsign(22))
  })

  test('unsign value', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    const signed = encryption.sign({ username: 'virk' })
    const unsigned = encryption.unsign(signed)
    assert.deepEqual(unsigned, { username: 'virk' })
  })

  test('return null when unable to decode it', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    assert.isNull(encryption.unsign('hello.world'))
  })

  test('return null when hash separator is missing', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    assert.isNull(encryption.unsign('helloworld'))
  })

  test('return null when hash was touched', ({ assert }) => {
    const encryption = new MessageVerifier(SECRET)
    const signed = encryption.sign({ username: 'virk' })
    assert.isNull(encryption.unsign(signed.slice(0, -2)))
  })
})
