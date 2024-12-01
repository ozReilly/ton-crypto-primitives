/**
 * Copyright (c) Whales Corp. 
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// export async function pbkdf2_sha512(key: string | Buffer, salt: string | Buffer, iterations: number, keyLen: number): Promise<Buffer> {
//     const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
//     const saltBuffer = typeof salt === 'string' ? Buffer.from(salt, 'utf-8') : salt;
//     let pbkdf2 = require('react-native-fast-pbkdf2').default;
//     let res = await pbkdf2.derive(keyBuffer.toString('base64'), saltBuffer.toString('base64'), iterations, keyLen, 'sha-512');
//     return Buffer.from(res, 'base64');
// }

import CryptoJS from 'crypto-js';

export async function pbkdf2_sha512(key, salt, iterations, keyLen) {
    // Convert key and salt to the correct format (UTF-8 encoded string)
    const keyBuffer = typeof key === 'string' ? key : Buffer.from(key).toString('utf-8');
    const saltBuffer = typeof salt === 'string' ? salt : Buffer.from(salt).toString('utf-8');

    // Generate the PBKDF2 key using CryptoJS.PBKDF2
    const derivedKey = CryptoJS.PBKDF2(keyBuffer, saltBuffer, {
        keySize: keyLen / 32,  // keyLen in bits, divided by 32 to convert to words (32 bits per word)
        iterations: iterations,
        hasher: CryptoJS.algo.SHA512  // Use SHA-512 hash function
    });

    // Convert the derived key to a Buffer
    return Buffer.from(derivedKey.toString(CryptoJS.enc.Base64), 'base64');
}
