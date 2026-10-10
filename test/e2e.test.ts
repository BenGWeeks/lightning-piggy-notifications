// End to end: a real watcher against an in-memory relay. Register over Nostr,
// publish a zap receipt / DM gift wrap, and check a (mocked) push goes out —
// then an invalid-token response removes the registration.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { nwcProofMessage } from '../src/registration.js';
import { createRumor, createSeal, createWrap } from 'nostr-tools/nip59';
import type { PushNotification, PushResult, PushSender } from '../src/push/types.js';
import type { Device } from '../src/store.js';
import { Watcher } from '../src/watcher.js';
import { FCM_TOKEN, makeRegistrationWrap, MiniRelay, regContent, testConfig, waitFor } from './helpers.js';

describe('watcher end to end', () => {
  let relay: MiniRelay;
  let watcher: Watcher;
  let sent: { device: Device; n: PushNotification }[];
  let result: PushResult;
  const watcherSk = generateSecretKey();
  const userSk = generateSecretKey();
  const userPk = getPublicKey(userSk);
  const strangerSk = generateSecretKey();

  beforeEach(async () => {
    relay = new MiniRelay();
    await relay.start();
    sent = [];
    result = 'ok';
    const sender: PushSender = {
      send: async (device, n) => {
        sent.push({ device, n });
        return result;
      },
    };
    const cfg = testConfig({ secretKey: watcherSk, relays: [relay.url] });
    cfg.limits.coalesceWindowSec = 1;
    watcher = new Watcher(cfg, { senders: { fcm: sender, apns: sender } });
    await watcher.start();
  });

  afterEach(async () => {
    await watcher.stop();
    await relay.stop();
  });

  async function register(over: Record<string, unknown> = {}) {
    const rebuilds = watcher.stats.rebuilds;
    const wrap = makeRegistrationWrap(userSk, watcher.pubkey, regContent({ relays: [relay.url], ...over }));
    relay.publish(wrap);
    // registration -> debounced rebuild -> the user's REQs go out; give the relay a moment to answer them
    await waitFor(() => watcher.readyStatus().registrations === 1 && watcher.stats.rebuilds > rebuilds);
    await new Promise((r) => setTimeout(r, 150));
  }

  it('publishes its kind-10050 inbox relay list', async () => {
    await waitFor(() => relay.events.some((e) => e.kind === 10050));
    const ev = relay.events.find((e) => e.kind === 10050)!;
    expect(ev.pubkey).toBe(watcher.pubkey);
    expect(ev.tags).toEqual([['relay', relay.url]]);
  });

  it('registers over Nostr and pushes a generic zap notification', async () => {
    await register();
    const zap = finalizeEvent(
      { kind: 9735, created_at: Math.floor(Date.now() / 1000), tags: [['p', userPk], ['P', getPublicKey(strangerSk)]], content: '' },
      strangerSk,
    );
    relay.publish(zap);
    relay.publish(zap); // duplicate delivery is deduped
    await waitFor(() => sent.length === 1);
    expect(sent[0]!.n).toEqual({ category: 'zap', count: 1 });
    expect(sent[0]!.device.token).toBe(FCM_TOKEN);
    expect(sent[0]!.device.app).toBe('com.lightningpiggy.app');
  });

  it('notifies for gift-wrapped DMs streamed after EOSE but not stored ones', async () => {
    // A stored wrap from before the watcher subscribed must not notify.
    const old = createWrap(createSeal(createRumor({ kind: 14, content: 'hi', tags: [['p', userPk]] }, strangerSk), strangerSk, userPk), userPk);
    relay.publish(old);
    await register();
    await new Promise((r) => setTimeout(r, 300));
    expect(sent).toHaveLength(0);
    const fresh = createWrap(createSeal(createRumor({ kind: 14, content: 'hey', tags: [['p', userPk]] }, strangerSk), strangerSk, userPk), userPk);
    relay.publish(fresh);
    await waitFor(() => sent.length === 1);
    expect(sent[0]!.n.category).toBe('dm');
  });

  it('ignores forged events and the user own events', async () => {
    await register();
    const now = Math.floor(Date.now() / 1000);
    const own = finalizeEvent({ kind: 1, created_at: now, tags: [['p', userPk]], content: 'me' }, userSk);
    const forged = { ...finalizeEvent({ kind: 1, created_at: now, tags: [['p', userPk]], content: 'x' }, strangerSk), sig: 'f'.repeat(128) };
    const stale = finalizeEvent({ kind: 1, created_at: now - 3600, tags: [['p', userPk]], content: 'old' }, strangerSk);
    relay.publish(own);
    relay.publish(forged);
    relay.publish(stale);
    await new Promise((r) => setTimeout(r, 300));
    expect(sent).toHaveLength(0);
  });

  it('removes the registration when the push service reports an invalid token', async () => {
    await register();
    result = 'invalid-token';
    relay.publish(finalizeEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [['p', userPk]], content: '' }, strangerSk));
    await waitFor(() => sent.length === 1);
    await waitFor(() => watcher.readyStatus().registrations === 0);
  });

  it('pushes NWC payment notifications only from the registered wallet', async () => {
    const clientSk = generateSecretKey();
    const walletSk = generateSecretKey();
    const client = getPublicKey(clientSk);
    const wallet = getPublicKey(walletSk);
    const proof = bytesToHex(schnorr.sign(nwcProofMessage(userPk, wallet), clientSk));
    await register({ categories: { payment: true }, nwc: [{ client, wallet, proof }] });
    const now = Math.floor(Date.now() / 1000);
    relay.publish(finalizeEvent({ kind: 23197, created_at: now, tags: [['p', client]], content: 'x' }, strangerSk)); // impostor
    relay.publish(finalizeEvent({ kind: 23197, created_at: now, tags: [['p', client]], content: 'y' }, walletSk));
    await waitFor(() => sent.length === 1);
    await new Promise((r) => setTimeout(r, 200));
    expect(sent).toHaveLength(1);
    expect(sent[0]!.n.category).toBe('payment');
  });

  it('survives malformed events', async () => {
    const meta = { relay: relay.url, subId: 'x', mode: 'inbox' as const, preEose: false, subscribedAt: 0 };
    const base = { id: 'a'.repeat(64), pubkey: 'b'.repeat(64), created_at: 1, kind: 1059, content: '', sig: 'c'.repeat(128) };
    for (const bad of [null, 42, { ...base, tags: [null] }, { ...base, tags: [[1, 2]] }, { ...base, tags: 'p' }, { ...base, id: 'zz', tags: [] }]) {
      expect(() => watcher.onEvent(bad, meta)).not.toThrow();
      expect(() => watcher.onEvent(bad, { ...meta, mode: 'live' })).not.toThrow();
    }
  });

  it('a forged stored copy cannot suppress the genuine live gift wrap', async () => {
    const genuine = createWrap(createSeal(createRumor({ kind: 14, content: 'yo', tags: [['p', userPk]] }, strangerSk), strangerSk, userPk), userPk);
    relay.publish({ ...genuine, sig: '0'.repeat(128) }); // same id, invalid signature, served pre-EOSE
    await register();
    await new Promise((r) => setTimeout(r, 200));
    relay.publish(genuine);
    await waitFor(() => sent.length === 1);
  });

  it('retains only canonical NIP-01 fields from relay events', async () => {
    const wrap = makeRegistrationWrap(userSk, watcher.pubkey, regContent({ relays: [relay.url] }));
    const meta = { relay: relay.url, subId: 'x', mode: 'inbox' as const, preEose: false, subscribedAt: 0 };
    watcher.onEvent({ ...wrap, junk: 'x'.repeat(480_000) }, meta);
    expect(watcher['inboxBytes']).toBeLessThan(10_000);
    await waitFor(() => watcher.readyStatus().registrations === 1);
  });

  it('reports not-ready when the subscription plan overflows', async () => {
    watcher['planOverflow'] = 2;
    expect(watcher.readyStatus()).toMatchObject({ ready: false, plan_overflow: 2 });
  });

  it('unregisters', async () => {
    await register();
    const wrap = makeRegistrationWrap(userSk, watcher.pubkey, regContent({ action: 'unregister' }, Math.floor(Date.now() / 1000) + 1));
    relay.publish(wrap);
    await waitFor(() => watcher.readyStatus().registrations === 0);
  });
});
