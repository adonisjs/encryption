/*
* @adonisjs/encryption
*
* (c) Harminder Virk <virk@adonisjs.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

import ms from 'ms'
import Bourne from '@hapi/bourne'

/**
 * Hints dates with `d:` prefix to convert them back
 * to actual date objects
 */
function stringifyReplacer (key: string, value: any) {
  if (this[key] instanceof Date) {
    return `d:${value}`
  }
  return value
}

/**
 * Parses date string back to date instances
 */
function parseReviver (_: string, value: any) {
  return typeof (value) === 'string' && value.substring(0, 2) === 'd:'
    ? new Date(value.slice(2))
    : value
}

/**
 * Message builder exposes an API to JSON.stringify values by encoding purpose
 * and expiryDate inside them. It returns a readable string, which is the
 * output of `JSON.stringify`.
 *
 * Ideally, this class is meant to be used internally, but you are free to use
 * it for any other specific purposes.
 */
export class MessageBuilder {
  private getExpiryDate (expiresIn?: string | number): undefined | Date {
    if (!expiresIn) {
      return undefined
    }

    const expiryMs = typeof (expiresIn) === 'string' ? ms(expiresIn) : expiresIn
    if (expiryMs === undefined || expiryMs === null) {
      throw new Error(`Invalid value for expiresIn "${expiresIn}"`)
    }

    return new Date(Date.now() + expiryMs)
  }

  /**
   * Returns a boolean telling, if message has been expired or not
   */
  private isExpired (message: any) {
    if (!message.expiryDate) {
      return false
    }

    if (message.expiryDate instanceof Date === false) {
      return true
    }

    return message.expiryDate < new Date()
  }

  /**
   * Builds a message by encoding expiry and purpose inside it
   */
  public build (message: any, expiresIn?: string | number, purpose?: string) {
    const expiryDate = this.getExpiryDate(expiresIn)
    return JSON.stringify({ message, purpose, expiryDate }, stringifyReplacer)
  }

  /**
   * Verifies the message for expiry and purpose
   */
  public verify<T extends any> (message: any, purpose?: string): null | T {
    try {
      const parsed = Bourne.parse(message, parseReviver, {
        protoAction: 'remove',
      })

      /**
       * Ensure purposes are same
       */
      if (parsed.purpose !== purpose) {
        return null
      }

      /**
       * Ensure isn't expired
       */
      if (this.isExpired(parsed)) {
        return null
      }

      return parsed.message
    } catch (error) {
      return null
    }
  }
}
