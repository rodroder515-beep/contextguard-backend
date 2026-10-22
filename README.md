# ContextGuard Standalone Backend

ContextGuard is a standalone Node.js + Express + TypeScript backend that enforces context-aware data privacy, task-relevance scoring, and destination-specific authorization before data leaves an AI workflow boundary.

---

## Render Deployment Quick Reference

- **Runtime:** `Node` (Node.js >= 20)
- **Build Command:** `npm install && npm run server:build`
- **Start Command:** `npm run server:start`
- **Health Check Path:** `/health`
- **Host / Port Binding:** Listens on `0.0.0.0` using `process.env.PORT` (defaults to `4000` locally).

> Note: `typescript`, `esbuild` and `tsx` are devDependencies. Render runs `npm install` with dev dependencies by default (unless `NODE_ENV=production` is set *before* install). If your build skips devDependencies, use `npm install --include=dev && npm run server:build` as the Build Command.

### Required Render Environment Variables

| Variable | Example Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Enables strict production CORS enforcement. |
| `ALLOWED_ORIGINS` | `https://your-app.vercel.app` | Comma-separated list of permitted frontend origins. |
| `ANALYSIS_TTL_MS` | `300000` | Optional TTL for in-memory analysis tokens in ms (default: 5 minutes). |
| `PORT` | *(Auto-injected by Render)* | Port the Express server binds to on `0.0.0.0`. |

---

## API Endpoints

1. `GET /health` - Service liveness and ephemeral in-memory storage telemetry.
2. `GET /api/options` - Authoritative destination profiles (`external-llm`, `mcp-plugin`, `support-crm`, `slack-bot`), preset workflow scenarios, and supported entity categories.
3. `POST /api/analyze` - Evaluates `rawPrompt`, `taskObjective`, `destinationId`, and optional `decisionOverrides`. Enforces non-weakening override rules, masks sensitive values, stores safe metadata in memory, and returns `analysisId` and `sanitizedPayloadSha256`.
4. `POST /api/submit-approved` - Validates `analysisId`, checks destination match, recomputes and verifies `sanitizedPayloadSha256` in constant time (`crypto.timingSafeEqual`), rejects `HALT_OUTBOUND` requests (`403`), enforces one-time token consumption (`409` on replay, `410` on expiry), and returns `status: "VALIDATED_NOT_SENT"`.
5. `GET /api/audit` - Returns the zero-secret-retention in-memory audit log ring buffer (max 200 entries; excludes raw prompts, raw entity values, and free-text task objectives).
6. `POST /api/evaluate` - Executes the 32-case synthetic evaluation benchmark comparing:
   - **A.** Keyword-Only Static DLP
   - **B.** Relevance Without Destination Auth
   - **C.** ContextGuard (Task Relevance + Destination Authorization Policy)

---

## Local Development & Testing

```bash
npm install            # install dependencies
npm run server:dev     # dev server with hot reload (port 4000)
npm run server:build   # type-check + bundle to dist-server/index.js
npm run server:start   # run the production bundle
npm run test:server    # API, security, and evaluation benchmark tests
```

---

## Prototype Architecture & Security Notes

- **Self-contained:** All policy-engine logic lives in `server/engine.ts` and `server/types.ts`, with no dependency on frontend files.
- **In-memory ephemeral storage:** Active analysis tokens and audit logs are held in process memory (`server/store.ts`) and reset on restart. Not suitable for multi-instance deployments.
- **Zero raw secret retention:** Raw prompts, raw sensitive tokens, and raw free-text task objectives are never stored or written to audit logs.
- **Prototype gatekeeper mode:** No live external LLM or webhook connector is invoked; validated submissions return `VALIDATED_NOT_SENT`.
