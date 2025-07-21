// Author: Tamaaxzcw
// GitHub: https://github.com/Tamaaxzcw

import {
    createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes,
} from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const SALT_SIZE = 16;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const KEY_DERIVATION_ALGO = 'sha512';
const ITERATIONS = 250000;
const KEY_SIZE = 32;

export function encrypt(text: string, secret: string): string {
    const salt = randomBytes(SALT_SIZE);
    const iv = randomBytes(IV_SIZE);
    const key = pbkdf2Sync(secret, salt, ITERATIONS, KEY_SIZE, KEY_DERIVATION_ALGO);

    const cipher = createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

export function decrypt(encryptedPayload: string, secret: string): string {
    const data = Buffer.from(encryptedPayload, 'base64');
    const salt = data.subarray(0, SALT_SIZE);
    const iv = data.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
    const tag = data.subarray(SALT_SIZE + IV_SIZE, SALT_SIZE + IV_SIZE + TAG_SIZE);
    const encryptedText = data.subarray(SALT_SIZE + IV_SIZE + TAG_SIZE);

    const key = pbkdf2Sync(secret, salt, ITERATIONS, KEY_SIZE, KEY_DERIVATION_ALGO);

    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString('utf8');
}
