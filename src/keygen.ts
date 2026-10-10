// Generate the watcher's secrets without ever printing them.
//   node dist/keygen.js nostr <path>   -> hex Nostr key (mode 600), prints the npub
//   node dist/keygen.js token <path>   -> 32-byte token-encryption key (mode 600)
//   node dist/keygen.js npub <path>    -> prints the npub of an existing key file
// Refuses to overwrite an existing file: losing the Nostr key changes the npub
// every installed app has built in.

import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { npubEncode } from 'nostr-tools/nip19';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { parseSecretKey } from './config.js';

const [mode, path] = process.argv.slice(2);
const out = (s: string) => process.stdout.write(s + '\n');

if (!path || !['nostr', 'token', 'npub'].includes(mode ?? '')) {
  process.stderr.write('usage: keygen.js nostr|token|npub <path>\n');
  process.exit(2);
}

if (mode === 'npub') {
  out(npubEncode(getPublicKey(parseSecretKey(readFileSync(path, 'utf8')))));
} else if (mode === 'nostr') {
  const sk = generateSecretKey();
  writeFileSync(path, bytesToHex(sk) + '\n', { mode: 0o600, flag: 'wx' });
  out(npubEncode(getPublicKey(sk)));
} else {
  writeFileSync(path, randomBytes(32).toString('hex') + '\n', { mode: 0o600, flag: 'wx' });
  out('token key written');
}
