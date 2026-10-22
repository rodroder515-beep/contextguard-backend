import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { apiRouter } from './routes.ts';

dotenv.config();

const DEFAULT_DEV_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
];

function getAllowedOrigins(): Set<string> {
  const isProd = process.env.NODE_ENV === 'production';
  const raw = process.env.ALLOWED_ORIGINS;
  if (raw && raw.trim()) {
    return new Set(
      raw
        .split(',')
        .map((s) => s.trim().replace(/^["']|["']$/g, ''))
        .filter((s) => s.length > 0 && (!isProd || s !== '*'))
    );
  }
  return isProd ? new Set() : new Set(DEFAULT_DEV_ORIGINS);
}

export const app = express();
app.disable('x-powered-by');

app.use((req: Request, res: Response, next: NextFunction) => {
  res.vary('Origin');
  const origin = req.headers.origin;
  const allowed = getAllowedOrigins();

  if (origin) {
    if (allowed.has(origin) || (process.env.NODE_ENV !== 'production' && allowed.has('*'))) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    } else if (req.method === 'OPTIONS') {
      return res.status(403).json({ error: 'CORS_ORIGIN_DENIED', message: 'Origin not allowed.' });
    }
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: '32kb' }));
app.use(apiRouter);

app.use((_req: Request, res: Response) => {
  return res.status(404).json({ error: 'NOT_FOUND', message: 'Endpoint not found.' });
});

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const errorObj = err as { type?: string; status?: number };
  if (errorObj?.type === 'entity.too.large' || errorObj?.status === 413) {
    return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds 32KB.' });
  }
  if (errorObj?.type === 'entity.parse.failed' || errorObj?.status === 400) {
    return res.status(400).json({ error: 'MALFORMED_JSON', message: 'Invalid JSON body.' });
  }
  return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'Internal server error.' });
});

// Do not start a listener when imported by tests (NODE_ENV=test, or running under the node test runner).
const isTestRun = process.env.NODE_ENV === 'test' || Boolean(process.env.NODE_TEST_CONTEXT);

if (!isTestRun) {
  const PORT = Number(process.env.PORT) || 4000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ContextGuard API listening on http://0.0.0.0:${PORT}`);
  });
}

export default app;
