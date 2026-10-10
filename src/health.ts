import http from 'node:http';

export interface ReadyStatus {
  ready: boolean;
  [k: string]: unknown;
}

/** Tiny /health + /ready server. Bind it to localhost (or a container port published on 127.0.0.1). */
export function startHealthServer(host: string, port: number, ready: () => ReadyStatus): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    if (req.method !== 'GET') {
      res.writeHead(405).end();
      return;
    }
    const path = (req.url ?? '').split('?')[0];
    if (path === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"status":"ok"}');
      return;
    }
    if (path === '/ready') {
      const s = ready();
      res.writeHead(s.ready ? 200 : 503, { 'content-type': 'application/json' }).end(JSON.stringify(s));
      return;
    }
    res.writeHead(404).end();
  });
  server.requestTimeout = 5_000;
  server.headersTimeout = 5_000;
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}
