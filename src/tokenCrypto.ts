// At-rest crypto for the registrations database. Everything identifying is
// either encrypted (AES-256-GCM, with associated data binding each ciphertext
// to its row) or replaced by a keyed HMAC used only as a lookup index, so a
// copy of the database file alone yields no tokens, pubkeys, relays or NWC
// keys. All subkeys are derived (HKDF-SHA256, distinct labels) from one
// 32-byte master key held in a secret file:
//
//   token enc  - device tokens
//   token mac  - token_hash = HMAC(platform, app, token)
//   row enc    - the identity blob {user pubkey, relays, NWC connections}
//   index mac  - user_idx = HMAC("user", pubkey), notified-event id hashes

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';

const VERSION = 1;

function derive(master: Buffer, label: string): Buffer {
  return Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), label, 32));
}

function seal(key: Buffer, plaintext: string, aad: string): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, ct, c.getAuthTag()]);
}

function open(key: Buffer, blob: Buffer, aad: string): string {
  if (blob.length < 1 + 12 + 16 || blob[0] !== VERSION) throw new Error('bad ciphertext');
  const iv = blob.subarray(1, 13);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(13, blob.length - 16);
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

export class TokenCrypto {
  private readonly encKey: Buffer;
  private readonly macKey: Buffer;
  private readonly rowKey: Buffer;
  private readonly idxKey: Buffer;

  constructor(masterKey: Buffer) {
    if (masterKey.length !== 32) throw new Error('token master key must be 32 bytes');
    this.encKey = derive(masterKey, 'lp-watcher token enc v1');
    this.macKey = derive(masterKey, 'lp-watcher token mac v1');
    this.rowKey = derive(masterKey, 'lp-watcher row enc v1');
    this.idxKey = derive(masterKey, 'lp-watcher index mac v1');
  }

  /** Stable, non-reversible lookup key for a (platform, app, token) triple. */
  tokenHash(platform: string, app: string, token: string): string {
    return createHmac('sha256', this.macKey).update(`${platform}\0${app}\0${token}`).digest('hex');
  }

  /** Keyed lookup index for an identifier (`domain` separates uses, e.g. "user", "event"). */
  index(domain: string, value: string): string {
    return createHmac('sha256', this.idxKey).update(`${domain}\0${value}`).digest('hex');
  }

  /** `aad` binds the ciphertext to its row so it can't be swapped between rows. */
  encrypt(token: string, aad: string): Buffer {
    return seal(this.encKey, token, aad);
  }

  decrypt(blob: Buffer, aad: string): string {
    return open(this.encKey, blob, aad);
  }

  encryptRow(plaintext: string, aad: string): Buffer {
    return seal(this.rowKey, plaintext, aad);
  }

  decryptRow(blob: Buffer, aad: string): string {
    return open(this.rowKey, blob, aad);
  }
}
