import { loadConfig } from './config.js';
import { log, setLogLevel } from './log.js';
import { Watcher } from './watcher.js';

// Files we create (the SQLite db + WAL) are private to the service user.
process.umask(0o077);

async function main(): Promise<void> {
  // better-sqlite3's native addon needs Node-API 10 (Node >= 22.14); older runtimes crash natively.
  if (Number(process.versions.napi) < 10) {
    throw new Error(`Node-API ${process.versions.napi} is too old: run Node ^22.14.0 or >= 24`);
  }
  const cfg = loadConfig();
  setLogLevel(cfg.logLevel);
  const watcher = new Watcher(cfg);
  await watcher.start();

  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    log.info('shutting down', { signal });
    const force = setTimeout(() => process.exit(1), 20_000);
    force.unref();
    watcher
      .stop()
      .then(() => process.exit(0))
      .catch((e: unknown) => {
        log.error('shutdown error', { err: e as Error });
        process.exit(1);
      });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

/** `node dist/index.js healthcheck` — used by the container HEALTHCHECK (no curl in the image). */
async function healthcheck(): Promise<void> {
  const bind = process.env.WATCHER_HEALTH_BIND || '127.0.0.1:8080';
  const [host, port] = bind.split(':');
  const target = host === '0.0.0.0' ? '127.0.0.1' : host;
  try {
    const res = await fetch(`http://${target}:${port}/health`, { signal: AbortSignal.timeout(5_000) });
    process.exit(res.status === 200 ? 0 : 1);
  } catch {
    process.exit(1);
  }
}

process.on('unhandledRejection', (e) => log.error('unhandled rejection', { err: e as Error }));

if (process.argv[2] === 'healthcheck') {
  void healthcheck();
} else {
  main().catch((e: unknown) => {
    log.error('fatal', { err: e as Error });
    process.exit(1);
  });
}
