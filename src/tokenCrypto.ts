// Device tokens are encrypted at rest (AES-256-GCM) and indexed by an HMAC,
// so a copy of the database alone yields no usable tokens. Both subkeys are
// derived from one 32-byte master key held in a secret file.

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';

export class TokenCrypto {
  private readonly encKey: Buffer;
  private readonly macKey: Buffer;

  constructor(masterKey: Buffer) {
    if (masterKey.length !== 32) throw new Error('token master key must be 32 bytes');
    this.encKey = Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'lp-watcher token enc v1', 32));
    this.macKey = Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'lp-watcher token mac v1', 32));
  }

  /** Stable, non-reversible lookup key for a (platform, app, token) triple. */
  tokenHash(platform: string, app: string, token: string): string {
    return createHmac('sha256', this.macKey).update(`${platform}\0${app}\0${token}`).digest('hex');
  }

  /** `aad` binds the ciphertext to its row so it can't be swapped between rows. */
  encrypt(token: string, aad: string): Buffer {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.encKey, iv);
    c.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([c.update(token, 'utf8'), c.final()]);
    return Buffer.concat([Buffer.from([1]), iv, ct, c.getAuthTag()]);
  }

  decrypt(blob: Buffer, aad: string): string {
    if (blob.length < 1 + 12 + 16 || blob[0] !== 1) throw new Error('bad token ciphertext');
    const iv = blob.subarray(1, 13);
    const tag = blob.subarray(blob.length - 16);
    const ct = blob.subarray(13, blob.length - 16);
    const d = createDecipheriv('aes-256-gcm', this.encKey, iv);
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  }
}
