import * as argon2 from 'argon2';
import * as crypto from 'node:crypto'

export async function passwordHash(password: string, salt: string): Promise<string> {
    return argon2.hash(password + salt);
}

export async function passwordVerify(password: string, salt: string, hash: string): Promise<boolean> {
    if (!hash || !salt) return false;
    return argon2.verify(hash, password + salt);
}

export async function generateRandomSalt(): Promise<string> {
    return crypto.randomBytes(24).toString('hex');
}