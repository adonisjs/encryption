/*
* @adonisjs/encryption
*
* (c) Harminder Virk <virk@adonisjs.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

import test from 'japa'
import { MessageBuilder } from '../src/MessageBuilder'

test.group('MessageBuilder', () => {
  test('build a number as a message', (assert) => {
    const message = new MessageBuilder()
    assert.equal(message.build(22), '{"message":22}')
  })

  test('build a string as a message', (assert) => {
    const message = new MessageBuilder()
    assert.equal(message.build('hello'), '{"message":"hello"}')
  })

  test('build a boolean as a message', (assert) => {
    const message = new MessageBuilder()
    assert.equal(message.build(true), '{"message":true}')
  })

  test('build a date as a message', (assert) => {
    const message = new MessageBuilder()
    const date = new Date()
    assert.equal(message.build(date), `{"message":"d:${date.toISOString()}"}`)
  })

  test('return message value after verification', (assert) => {
    const message = new MessageBuilder()
    assert.equal(message.verify(message.build(22)), 22)
  })

  test('return null when purpose was defined during build, but not verify', (assert) => {
    const message = new MessageBuilder()
    assert.isNull(message.verify(message.build(22, undefined, 'login')))
  })

  test('return null when no purpose was defined during build', (assert) => {
    const message = new MessageBuilder()
    assert.isNull(message.verify(message.build(22), 'login'))
  })

  test('return null when purpose mismatch', (assert) => {
    const message = new MessageBuilder()
    assert.isNull(message.verify(message.build(22, undefined, 'register'), 'login'))
  })

  test('return null when message has been expired', (assert) => {
    const message = new MessageBuilder()
    assert.isNull(message.verify(message.build(22, -10)))
  })

  test('return message when not expired', (assert) => {
    const message = new MessageBuilder()
    assert.equal(message.verify(message.build(22, '10 hours')), 22)
  })

  test('convert date to date instances on verify', (assert) => {
    const message = new MessageBuilder()
    const date = new Date()
    assert.deepEqual(message.verify(message.build(date, '10 hours')), new Date(date))
  })
})
