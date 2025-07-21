// Author: Tamaaxzcw
// GitHub: https://github.com/Tamaaxzcw
'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const SALT_SIZE = 16;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const KEY_DERIVATION_ALGO = 'sha512';
const ITERATIONS = 250000;
const KEY_SIZE = 32;

function encrypt(text, secret) {
    const salt = crypto.randomBytes(SALT_SIZE);
    const iv = crypto.randomBytes(IV_SIZE);
    const key = crypto.pbkdf2Sync(secret, salt, ITERATIONS, KEY_SIZE, KEY_DERIVATION_ALGO);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

function decrypt(encryptedPayload, secret) {
    try {
        const data = Buffer.from(encryptedPayload, 'base64');
        const salt = data.subarray(0, SALT_SIZE);
        const iv = data.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
        const tag = data.subarray(SALT_SIZE + IV_SIZE, SALT_SIZE + IV_SIZE + TAG_SIZE);
        const encryptedText = data.subarray(SALT_SIZE + IV_SIZE + TAG_SIZE);

        const key = crypto.pbkdf2Sync(secret, salt, ITERATIONS, KEY_SIZE, KEY_DERIVATION_ALGO);

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        throw new Error("Decryption failed. Check key or data integrity.");
    }
}

module.exports = { encrypt, decrypt };

// Example
const secretKey = "tamaaxzcw-key";
const originalText = "Pesan ini dienkripsi di JavaScript.";
const encrypted = encrypt(originalText, secretKey);
console.log("Encrypted:", encrypted);
const decrypted = decrypt(encrypted, secretKey);
console.log("Decrypted:", decrypted);
