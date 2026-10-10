// Structured JSON logging. Privacy rule: never log device tokens, event
// content, or full pubkeys/event ids — use `short()` for identifiers.

type Level = 'debug' | 'info' | 'warn' | 'error';
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let threshold: number = ORDER.info;
let sink: (line: string) => void = (line) => process.stdout.write(line + '\n');

export function setLogLevel(level: string): void {
  threshold = ORDER[(level as Level) in ORDER ? (level as Level) : 'info'];
}

/** Test hook: capture log lines. */
export function setLogSink(fn: (line: string) => void): void {
  sink = fn;
}

/** First 8 chars of an identifier — enough to correlate, not to identify. */
export function short(id: string | undefined | null): string {
  if (!id) return '-';
  return id.length <= 8 ? id : `${id.slice(0, 8)}…`;
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
