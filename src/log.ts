// Structured JSON logging.
//
// Privacy rules:
// * Never log device tokens, event content, raw network error messages, or
//   full pubkeys/event ids.
// * At `info` and above, never log anything that identifies a user or device
//   (not even truncated): per-event and per-delivery activity is aggregated
//   into a periodic `activity` line (see activity.ts). Per-user detail is
//   `debug` only, and there identifiers go through `pseudonym()`, a keyed hash
//   with a random per-process key, so lines can be correlated within one run
//   but not linked to the database (or to another run's logs).

import { createHmac, randomBytes } from 'node:crypto';

type Level = 'debug' | 'info' | 'warn' | 'error';
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let threshold: number = ORDER.info;
let sink: (line: string) => void = (line) => process.stdout.write(line + '\n');
const PSEUDONYM_KEY = randomBytes(32);

export function setLogLevel(level: string): void {
  threshold = ORDER[(level as Level) in ORDER ? (level as Level) : 'info'];
}

/** Test hook: capture log lines. */
export function setLogSink(fn: (line: string) => void): void {
  sink = fn;
}

/** Is `level` currently emitted? (skip building expensive debug fields otherwise) */
export function logs(level: Level): boolean {
  return ORDER[level] >= threshold;
}

/**
 * Opaque per-process pseudonym for an identifier (debug logs only): stable
 * within this process, unlinkable to the stored pubkey/token or across restarts.
 */
export function pseudonym(id: string | undefined | null): string {
  if (!id) return '-';
  return createHmac('sha256', PSEUDONYM_KEY).update(id).digest('hex').slice(0, 10);
}

function emit(level: Level, msg: string, fields?: Record<string, unknown>): void {
  if (ORDER[level] < threshold) return;
  const rec: Record<string, unknown> = { ts: new Date().toISOString(), level, msg };
  if (fields) {
    for (const [k, v] of Object.entries(fields)) {
      if (k === 'ts' || k === 'level' || k === 'msg') continue; // reserved
      rec[k] = v instanceof Error ? v.message : v;
    }
  }
  sink(JSON.stringify(rec));
}

export const log = {
  debug: (msg: string, f?: Record<string, unknown>) => emit('debug', msg, f),
  info: (msg: string, f?: Record<string, unknown>) => emit('info', msg, f),
  warn: (msg: string, f?: Record<string, unknown>) => emit('warn', msg, f),
  error: (msg: string, f?: Record<string, unknown>) => emit('error', msg, f),
};

/** Log-safe error: its code (e.g. ECONNREFUSED) or class name, never a raw message. */
export function errCode(e: unknown): string {
  const code = (e as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === 'string' ? code.slice(0, 40) : e instanceof Error ? e.name : 'unknown';
}
