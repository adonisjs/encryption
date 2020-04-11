/*
 * @adonisjs/encryption
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

/**
 * The binding for the given module is defined inside `providers/AppProvider.ts`
 * file.
 */
declare module '@ioc:Adonis/Core/Encryption' {
  export type EncryptionConfigContract = {
    key: string,
    hmac: boolean,
    reviver: (key: string, value: string) => any,
  }

  export interface EncryptionContract {
    /**
     * Encrypt a given piece of value using the app secret. A wide range of
     * data types are supported.
     *
     * - String
     * - Arrays
     * - Objects
     * - Booleans
     * - Numbers
     * - Dates
     *
     * Encrypt/decrypting a date object will result in returning a date string.
     */
    encrypt (payload: any): string,

    /**
     * Decrypt a previously encrypted value
     */
    decrypt (payload: string): any,

    /**
     * Create a new instance of encryption with custom runtime config
     */
    create (options?: Partial<EncryptionConfigContract>): EncryptionContract,

    /**
     * BASE64 Encode value
     */
    base64Encode (arrayBuffer: ArrayBuffer | SharedArrayBuffer): string,
    base64Encode (data: string, encoding?: BufferEncoding): string,

    /**
     * BASE64 decode the encoded value
     */
    base64Decode (encoded: string | Buffer, encoding?: BufferEncoding): string,
  }

  const Encryption: EncryptionContract
  export default Encryption
}
