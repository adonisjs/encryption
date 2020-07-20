/*
 * @adonisjs/events
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import test from 'japa'
import { join } from 'path'
import { Registrar, Ioc } from '@adonisjs/fold'
import { Config } from '@adonisjs/config/build/standalone'

import { Encryption } from '../src/Encryption'

const SECRET = 'averylongradom32charactersstring'

test.group('Encryption Provider', () => {
	test('register encryption provider', async (assert) => {
		const ioc = new Ioc()
		ioc.bind('Adonis/Core/Config', () => {
			return new Config({
				app: {
					appKey: SECRET,
				},
			})
		})

		const registrar = new Registrar(ioc, join(__dirname, '..'))
		await registrar.useProviders(['./providers/EncryptionProvider']).registerAndBoot()

		assert.instanceOf(ioc.use('Adonis/Core/Encryption'), Encryption)
		assert.deepEqual(ioc.use('Adonis/Core/Encryption'), ioc.use('Adonis/Core/Encryption'))
	})

	test('raise error when app is missing', async (assert) => {
		const ioc = new Ioc()
		ioc.bind('Adonis/Core/Config', () => {
			return new Config({
				app: {},
			})
		})

		const registrar = new Registrar(ioc, join(__dirname, '..'))
		await registrar.useProviders(['./providers/EncryptionProvider']).registerAndBoot()

		const fn = () => ioc.use('Adonis/Core/Encryption')
		assert.throw(
			fn,
			'E_MISSING_APP_KEY: Missing "app.appKey". Makes sure to define it inside the config file'
		)
	})
})
