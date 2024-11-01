// @ts-check
'use strict'

/**
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * It is **NOT RECOMMENDED** to use RSA for message encryption; asymmetric encryption is primarily used to encrypt keys.
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */



/**
 * An Asymmetric Encryption example demonstrating RSA encryption in NodeJS.
 * 
 * This is just an example demonstrating how to use asymmetric encryption with RSA.
 *
 * The reasons for this are as follows:
 * - The message size is limited by the key length. With a 2048-bit key, it is only possible to encrypt a message up to 256 bytes.
 * - The algorithm requires significant resources.
 *
 * For message encryption, it is better to use a hybrid approach.
 *
 * @description
 *
 * RSA encryption uses a pair of keys: a public key and a private key.
 *
 * - The public key is accessible to everyone and is used to encrypt data.
 * - The private key should be kept secret by the owner and is used to decrypt data encrypted with the public key.
 *
 * Data encrypted with the public key can only be decrypted with the corresponding private key, and vice versa.
 *
 * @author Paul K.
 */

import {
  generateKeyPairSync,
  KeyObject,
  privateDecrypt as decrypt,
  publicEncrypt as encrypt,
} from 'crypto'
import { logDetails, logSuccess } from '../utils.mjs'

/**
 * PKCS — a set of standards for cryptographic data developed by RSA Laboratories.
 *
 * **PKCS#1**: A format for storing RSA keys.
 * Both public and private keys use PKCS#1.
 * It defines formats for storing and transferring RSA public and private keys.
 * Used when compatibility with systems and applications expecting PKCS#1 key format is needed.
 * Adds "RSA" in the header/footer of the keys.
 *
 * **PEM (Privacy-Enhanced Mail)** - used for encoding cryptographic keys and other data in text form using Base64.
 * PEM format is convenient for exchanging cryptographic data in text form, which simplifies transmission and storage.
 * Due to the ASN.1 structure of PEM-formatted keys, keys start with common symbols: MIG for 1024-bit keys, MII for 2048- and 4096-bit keys.
 */
const KEY_OPTIONS = {
  type: 'pkcs1',
  format: 'pem',
}

/**
 * modulusLength — the length of the key. As the key length increases, security also increases, and it becomes possible to encrypt larger amounts of data. 
 * However, this also leads to a decrease in performance.
 */
const KEYS_PARAMS = {
  modulusLength: 2048,
  publicKeyEncoding: KEY_OPTIONS,
  privateKeyEncoding: KEY_OPTIONS,
}

/**
 * Decrypts a message with a private key from a base64-encoded encrypted string.
 *
 * @param {KeyObject} privateKey - The private key used for decryption.
 * @param {string} message - The base64-encoded encrypted message.
 * @returns {string} - The decrypted message as a string.
 */
const privateDecrypt = (privateKey, message) =>
  decrypt(privateKey, Buffer.from(message, 'base64')).toString()

/**
 * Encrypts a message as a base64 string using a public key.
 *
 * @param {KeyObject} publicKey - The public key used for encryption.
 * @param {string} message - The original text to encrypt.
 * @returns {string} - The encrypted message as a base64 string.
 */
const publicEncrypt = (publicKey, message) =>
  encrypt(publicKey, Buffer.from(message)).toString('base64')

/**
 * Generates key pairs for Alice and Bob.
 */
const { publicKey: ALICE_PUBLIC_KEY, privateKey: ALICE_PRIVATE_KEY } =
  generateKeyPairSync('rsa', KEYS_PARAMS)
const { publicKey: BOB_PUBLIC_KEY, privateKey: BOB_PRIVATE_KEY } =
  generateKeyPairSync('rsa', KEYS_PARAMS)

/**
 * Alice sends a message to Bob and encrypts it with Bob's public key.
 */
const msgAlice = 'Hello, Bob!'
const encryptedMsgAlice = publicEncrypt(BOB_PUBLIC_KEY, msgAlice)

logDetails(`Alice sends an encrypted message to Bob: ${encryptedMsgAlice}`)

/**
 * Bob receives the message from Alice and decrypts it with his private key.
 */
const decryptedMsgAlice = privateDecrypt(BOB_PRIVATE_KEY, encryptedMsgAlice)

logSuccess(`Bob receives the message from Alice: "${decryptedMsgAlice}"`)

logDetails('------------------------------------------------------------------')

/**
 * Bob sends a message to Alice and encrypts it with Alice's public key.
 */
const msgBob = 'Hello, Alice!'
const encryptedMsgBob = publicEncrypt(ALICE_PUBLIC_KEY, msgBob)
logDetails(`Bob sends an encrypted message to Alice: ${encryptedMsgBob}`)

/**
 * Alice receives the message from Bob and decrypts it with her private key.
 */
const decryptedMsgBob = privateDecrypt(ALICE_PRIVATE_KEY, encryptedMsgBob)

logSuccess(`Alice receives the message from Bob: "${decryptedMsgBob}"`)
