process.env.NODE_ENV = 'test';

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { memoryStore } from '../store.ts';

// Imported dynamically AFTER NODE_ENV is set (static imports are hoisted), so the app never starts its own listener.
const { default: app } = await import('../index.ts');

let server: http.Server;
let baseUrl = '';

test.before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});

test.beforeEach(() => {
  memoryStore.reset();
});

async function postJson(path: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

test('1. Health and options endpoints respond with expected structure and CORS Vary header', async () => {
  const healthRes = await fetch(`${baseUrl}/health`, { headers: { Origin: 'http://localhost:3000' } });
  assert.equal(healthRes.status, 200);
  assert.equal(healthRes.headers.get('access-control-allow-origin'), 'http://localhost:3000');
  assert.ok(healthRes.headers.get('vary')?.includes('Origin'));

  const disallowedPreflight = await fetch(`${baseUrl}/api/analyze`, {
    method: 'OPTIONS',
    headers: { Origin: 'https://evil.example.com' },
  });
  assert.equal(disallowedPreflight.status, 403);
  assert.equal(disallowedPreflight.headers.get('access-control-allow-origin'), null);

  const allowedPreflight = await fetch(`${baseUrl}/api/analyze`, {
    method: 'OPTIONS',
    headers: { Origin: 'http://localhost:5173' },
  });
  assert.equal(allowedPreflight.status, 204);
  assert.equal(allowedPreflight.headers.get('access-control-allow-origin'), 'http://localhost:5173');

  const optionsRes = await fetch(`${baseUrl}/api/options`);
  const optionsBody = await optionsRes.json();
  assert.equal(optionsRes.status, 200);
  assert.ok(optionsBody.destinations['external-llm']);
  assert.equal(optionsBody.scenarios.length, 4);
});

test('2. Rejects malformed overrides (arrays, unknown entity IDs, invalid values) and blocks policy weakening', async () => {
  const arrRes = await postJson('/api/analyze', {
    rawPrompt: 'Contact user@example.com',
    decisionOverrides: ['ALLOW'],
  });
  assert.equal(arrRes.status, 400);
  assert.equal(arrRes.body.error, 'INVALID_OVERRIDES_FORMAT');

  const unknownIdRes = await postJson('/api/analyze', {
    rawPrompt: 'Contact user@example.com',
    decisionOverrides: { 'entity-9': 'BLOCK' },
  });
  assert.equal(unknownIdRes.status, 400);
  assert.equal(unknownIdRes.body.error, 'UNKNOWN_OVERRIDE_ENTITY_ID');

  const badValue = await postJson('/api/analyze', {
    rawPrompt: 'Contact user@example.com',
    decisionOverrides: { 'entity-1': 'PERMIT' },
  });
  assert.equal(badValue.status, 400);
  assert.equal(badValue.body.error, 'INVALID_OVERRIDE_VALUE');

  const badDest = await postJson('/api/analyze', {
    rawPrompt: 'Hello',
    destinationId: 'constructor',
  });
  assert.equal(badDest.status, 400);
  assert.equal(badDest.body.error, 'INVALID_DESTINATION');

  const weakenAttempt = await postJson('/api/analyze', {
    rawPrompt: 'Evaluate Project Helios ($48.2M) and key sk_live_98a7f65c44b2109d',
    taskObjective: 'rotate key and summarize valuation memo',
    destinationId: 'mcp-plugin',
    decisionOverrides: { 'entity-1': 'REDACT', 'entity-2': 'ALLOW', 'entity-3': 'ALLOW' },
  });
  assert.equal(weakenAttempt.status, 200);
  assert.equal(weakenAttempt.body.entities[0].decision, 'BLOCK');
  assert.equal(weakenAttempt.body.entities[1].decision, 'REDACT');
  assert.equal(weakenAttempt.body.entities[2].decision, 'REDACT');
});

test('3. Excludes raw sensitive values, raw prompts, and raw taskObjectives from store and audit logs', async () => {
  const rawKey = 'sk_live_98a7f65c44b2109d';
  const rawEmail = 'elena.rostova@acme-bio.io';
  const anl = await postJson('/api/analyze', {
    rawPrompt: `Context dump: ${rawKey} and ${rawEmail}`,
    taskObjective: `rotate key ${rawKey} for ${rawEmail}`,
    destinationId: 'external-llm',
  });
  assert.equal(anl.status, 200);

  const inspect = memoryStore.inspectAnalysis(anl.body.analysisId);
  assert.equal(inspect.status, 'AVAILABLE');
  const storeText = JSON.stringify((inspect as { analysis: unknown }).analysis);
  assert.ok(!storeText.includes(rawKey));
  assert.ok(!storeText.includes(rawEmail));
  assert.ok(!storeText.includes('Context dump'));

  const auditRes = await fetch(`${baseUrl}/api/audit`);
  const auditText = await auditRes.text();
  assert.ok(!auditText.includes(rawKey));
  assert.ok(!auditText.includes(rawEmail));
});

test('4. Validates destination and payload hash before consuming token, prevents replay, and detects stored payload tampering', async () => {
  const anl = await postJson('/api/analyze', {
    rawPrompt: 'Contact sarah.connor@sky-shield.com regarding invoice amount $3,450.00.',
    taskObjective: 'Send customer billing invoice amount email to customer contact',
    destinationId: 'support-crm',
  });
  const { analysisId, sanitizedPayloadSha256 } = anl.body;

  // Destination mismatch does not consume token
  const wrongDest = await postJson('/api/submit-approved', { analysisId, destinationId: 'mcp-plugin' });
  assert.equal(wrongDest.status, 400);
  assert.equal(wrongDest.body.error, 'DESTINATION_MISMATCH');

  // Hash mismatch does not consume token
  const wrongHash = await postJson('/api/submit-approved', {
    analysisId,
    destinationId: 'support-crm',
    expectedSanitizedPayloadSha256: '0'.repeat(64),
  });
  assert.equal(wrongHash.status, 400);
  assert.equal(wrongHash.body.error, 'PAYLOAD_HASH_MISMATCH');

  // Valid submission succeeds and returns VALIDATED_NOT_SENT
  const okSubmit = await postJson('/api/submit-approved', {
    analysisId,
    destinationId: 'support-crm',
    expectedSanitizedPayloadSha256: sanitizedPayloadSha256,
  });
  assert.equal(okSubmit.status, 200);
  assert.equal(okSubmit.body.status, 'VALIDATED_NOT_SENT');

  // Replay attempt fails with 409
  const replay = await postJson('/api/submit-approved', { analysisId, destinationId: 'support-crm' });
  assert.equal(replay.status, 409);
  assert.equal(replay.body.error, 'ANALYSIS_ALREADY_SUBMITTED');

  // Stored payload tampering fails even when client omits expected hash
  const anl2 = await postJson('/api/analyze', {
    rawPrompt: 'Clean prompt',
    destinationId: 'external-llm',
  });
  memoryStore.tamperForTesting(anl2.body.analysisId, (rec) => {
    rec.sanitizedPrompt = 'Tampered in-memory payload';
  });
  const tamperedSubmit = await postJson('/api/submit-approved', {
    analysisId: anl2.body.analysisId,
    destinationId: 'external-llm',
  });
  assert.equal(tamperedSubmit.status, 409);
  assert.equal(tamperedSubmit.body.error, 'STORED_PAYLOAD_INTEGRITY_FAILURE');
});

test('5. Rejects expired analyses with 410 Gone and blocked analyses with 403 Forbidden', async () => {
  const expiredAnl = await postJson('/api/analyze', {
    rawPrompt: 'Benign workflow text',
    destinationId: 'external-llm',
  });
  memoryStore.tamperForTesting(expiredAnl.body.analysisId, (rec) => {
    rec.expiresAt = Date.now() - 1000;
  });
  const expiredSub = await postJson('/api/submit-approved', {
    analysisId: expiredAnl.body.analysisId,
    destinationId: 'external-llm',
  });
  assert.equal(expiredSub.status, 410);
  assert.equal(expiredSub.body.error, 'ANALYSIS_EXPIRED');

  const blockedAnl = await postJson('/api/analyze', {
    rawPrompt: 'Secret key sk_live_98a7f65c44b2109d',
    destinationId: 'external-llm',
  });
  const blockedSub = await postJson('/api/submit-approved', {
    analysisId: blockedAnl.body.analysisId,
    destinationId: 'external-llm',
  });
  assert.equal(blockedSub.status, 403);
  assert.equal(blockedSub.body.error, 'OUTBOUND_POLICY_BLOCKED');
});
