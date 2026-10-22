import { Router, Request, Response } from 'express';
import {
  DESTINATIONS,
  WORKFLOW_SCENARIOS,
  evaluateWorkflowContextServer,
} from './engine.ts';
import { DestinationId, PolicyDecision } from './types.ts';
import { memoryStore } from './store.ts';
import {
  hashPayload,
  isPlainObject,
  safeCompareHashes,
  toStoredEntityMetadata,
} from './security.ts';
import { runEvaluationBenchmark } from './evaluationSuite.ts';

export const apiRouter = Router();

const ALLOWED_DECISIONS = new Set<string>(['ALLOW', 'REDACT', 'BLOCK']);
const ENTITY_ID_REGEX = /^entity-[1-9]\d*$/;
const FORBIDDEN_KEYS = new Set<string>(['__proto__', 'constructor', 'prototype']);

apiRouter.get('/health', (_req: Request, res: Response) => {
  return res.json({
    status: 'ok',
    service: 'contextguard-api',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    storage: memoryStore.getStats(),
  });
});

apiRouter.get('/api/options', (_req: Request, res: Response) => {
  return res.json({
    destinations: DESTINATIONS,
    scenarios: WORKFLOW_SCENARIOS,
    supportedCategories: [
      'API_CREDENTIAL',
      'INFRASTRUCTURE_URI',
      'NATIONAL_ID',
      'CLINICAL_IDENTIFIER',
      'PROPRIETARY_CODENAME',
      'PII_CONTACT',
      'FINANCIAL_RECORD',
    ],
  });
});

apiRouter.post('/api/analyze', (req: Request, res: Response) => {
  if (!isPlainObject(req.body)) {
    return res.status(400).json({ error: 'INVALID_REQUEST_BODY', message: 'Request body must be a JSON object.' });
  }

  const { rawPrompt, taskObjective, destinationId, decisionOverrides } = req.body;

  if (typeof rawPrompt !== 'string' || !rawPrompt.trim()) {
    return res.status(400).json({ error: 'INVALID_INPUT', message: '"rawPrompt" is required and must be a non-empty string.' });
  }
  if (rawPrompt.length > 10000) {
    return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', message: '"rawPrompt" exceeds 10,000 characters.' });
  }
  if (taskObjective !== undefined && (typeof taskObjective !== 'string' || taskObjective.length > 500)) {
    return res.status(400).json({ error: 'INVALID_INPUT', message: '"taskObjective" must be a string up to 500 characters.' });
  }
  if (destinationId !== undefined && (typeof destinationId !== 'string' || !Object.prototype.hasOwnProperty.call(DESTINATIONS, destinationId))) {
    return res.status(400).json({ error: 'INVALID_DESTINATION', message: 'Unknown destinationId.' });
  }

  let validatedOverrides: Record<string, PolicyDecision> | undefined;
  if (decisionOverrides !== undefined) {
    if (!isPlainObject(decisionOverrides)) {
      return res.status(400).json({ error: 'INVALID_OVERRIDES_FORMAT', message: '"decisionOverrides" must be a plain object.' });
    }
    validatedOverrides = {};
    for (const [key, val] of Object.entries(decisionOverrides)) {
      if (FORBIDDEN_KEYS.has(key) || !ENTITY_ID_REGEX.test(key)) {
        return res.status(400).json({ error: 'INVALID_OVERRIDE_KEY', message: `Invalid override key "${key}".` });
      }
      if (typeof val !== 'string' || !ALLOWED_DECISIONS.has(val)) {
        return res.status(400).json({ error: 'INVALID_OVERRIDE_VALUE', message: `Invalid override value for "${key}".` });
      }
      validatedOverrides[key] = val as PolicyDecision;
    }
  }

  const effectiveDestId: DestinationId = (destinationId as DestinationId) || 'external-llm';
  const cleanObjective = typeof taskObjective === 'string' ? taskObjective.trim() : '';

  const { result: evaluation, unknownOverrideIds } = evaluateWorkflowContextServer(
    rawPrompt,
    cleanObjective,
    effectiveDestId,
    validatedOverrides
  );

  if (unknownOverrideIds.length > 0) {
    return res.status(400).json({
      error: 'UNKNOWN_OVERRIDE_ENTITY_ID',
      message: `Override key "${unknownOverrideIds[0]}" does not exist in detected entities.`,
    });
  }

  const sanitizedPayloadSha256 = hashPayload(evaluation.sanitizedPrompt);
  const storedEntities = evaluation.entities.map(toStoredEntityMetadata);

  const stored = memoryStore.saveAnalysis({
    destinationId: effectiveDestId,
    taskPurposeCategory: evaluation.taskPurposeCategory,
    sanitizedPrompt: evaluation.sanitizedPrompt,
    sanitizedPayloadSha256,
    overallAction: evaluation.overallAction,
    entities: storedEntities,
    metrics: evaluation.metrics,
    principleTriggered: evaluation.principleTriggered,
    principleSummary: evaluation.principleSummary,
  });

  memoryStore.addAuditEntry({
    eventType: 'ANALYSIS_PERFORMED',
    analysisId: stored.analysisId,
    destinationId: effectiveDestId,
    destinationName: evaluation.destination.name,
    taskPurposeCategory: evaluation.taskPurposeCategory,
    sanitizedPayloadSha256,
    overallAction: evaluation.overallAction,
    metrics: {
      totalDetected: evaluation.metrics.totalDetected,
      allowedCount: evaluation.metrics.allowedCount,
      redactedCount: evaluation.metrics.redactedCount,
      blockedCount: evaluation.metrics.blockedCount,
    },
    decisions: storedEntities.map((e) => ({
      entityId: e.id,
      category: e.category,
      maskedToken: e.maskedValue,
      relevanceLevel: e.relevanceLevel,
      defaultDecision: e.defaultDecision,
      decision: e.decision,
      ruleId: e.policyRuleId,
    })),
  });

  return res.json({
    analysisId: stored.analysisId,
    expiresAt: new Date(stored.expiresAt).toISOString(),
    canSubmit: evaluation.overallAction !== 'HALT_OUTBOUND',
    sanitizedPayloadSha256,
    ...evaluation,
  });
});

apiRouter.post('/api/submit-approved', (req: Request, res: Response) => {
  if (!isPlainObject(req.body)) {
    return res.status(400).json({ error: 'INVALID_REQUEST_BODY', message: 'Request body must be a JSON object.' });
  }

  const { analysisId, destinationId, expectedSanitizedPayloadSha256, expectedSanitizedPrompt } = req.body;

  if (typeof analysisId !== 'string' || !analysisId.trim()) {
    return res.status(400).json({ error: 'MISSING_ANALYSIS_ID', message: '"analysisId" is required.' });
  }
  if (typeof destinationId !== 'string' || !Object.prototype.hasOwnProperty.call(DESTINATIONS, destinationId)) {
    return res.status(400).json({ error: 'INVALID_DESTINATION', message: 'Valid "destinationId" is required.' });
  }

  const inspection = memoryStore.inspectAnalysis(analysisId);
  if (inspection.status === 'NOT_FOUND') {
    return res.status(404).json({ error: 'ANALYSIS_NOT_FOUND', message: 'Analysis ID not found.' });
  }
  if (inspection.status === 'EXPIRED') {
    return res.status(410).json({ error: 'ANALYSIS_EXPIRED', message: 'Analysis token has expired.' });
  }
  if (inspection.status === 'ALREADY_CONSUMED') {
    return res.status(409).json({ error: 'ANALYSIS_ALREADY_SUBMITTED', message: 'Analysis token already consumed.' });
  }

  const stored = inspection.analysis;

  // Validate destination match before consuming token
  if (destinationId !== stored.destinationId) {
    return res.status(400).json({ error: 'DESTINATION_MISMATCH', message: 'Destination does not match analyzed destination.' });
  }

  // Always recompute hash of stored.sanitizedPrompt and verify against stored.sanitizedPayloadSha256
  const recomputedHash = hashPayload(stored.sanitizedPrompt);
  if (!safeCompareHashes(recomputedHash, stored.sanitizedPayloadSha256)) {
    return res.status(409).json({ error: 'STORED_PAYLOAD_INTEGRITY_FAILURE', message: 'Stored sanitized payload failed hash verification.' });
  }

  // Validate optional client hash or prompt before consuming token
  if (expectedSanitizedPayloadSha256 !== undefined) {
    if (typeof expectedSanitizedPayloadSha256 !== 'string' || !safeCompareHashes(expectedSanitizedPayloadSha256, recomputedHash)) {
      return res.status(400).json({ error: 'PAYLOAD_HASH_MISMATCH', message: 'Supplied hash does not match sanitized payload.' });
    }
  }
  if (expectedSanitizedPrompt !== undefined) {
    if (typeof expectedSanitizedPrompt !== 'string' || !safeCompareHashes(hashPayload(expectedSanitizedPrompt), recomputedHash)) {
      return res.status(400).json({ error: 'PAYLOAD_ALTERED', message: 'Supplied prompt does not match sanitized payload.' });
    }
  }

  if (stored.overallAction === 'HALT_OUTBOUND' || stored.metrics.blockedCount > 0 || stored.entities.some((e) => e.decision === 'BLOCK')) {
    memoryStore.addAuditEntry({
      eventType: 'SUBMISSION_REJECTED',
      analysisId: stored.analysisId,
      destinationId: stored.destinationId,
      destinationName: DESTINATIONS[stored.destinationId].name,
      taskPurposeCategory: stored.taskPurposeCategory,
      sanitizedPayloadSha256: recomputedHash,
      overallAction: 'HALT_OUTBOUND',
      metrics: {
        totalDetected: stored.metrics.totalDetected,
        allowedCount: stored.metrics.allowedCount,
        redactedCount: stored.metrics.redactedCount,
        blockedCount: stored.metrics.blockedCount,
      },
      decisions: stored.entities.map((e) => ({
        entityId: e.id,
        category: e.category,
        maskedToken: e.maskedValue,
        relevanceLevel: e.relevanceLevel,
        defaultDecision: e.defaultDecision,
        decision: e.decision,
        ruleId: e.policyRuleId,
      })),
    });

    return res.status(403).json({
      error: 'OUTBOUND_POLICY_BLOCKED',
      message: 'Submission rejected due to BLOCK policy decision.',
      analysisId: stored.analysisId,
      overallAction: 'HALT_OUTBOUND',
    });
  }

  if (!memoryStore.consumeAnalysisAtomically(analysisId)) {
    return res.status(409).json({ error: 'ANALYSIS_ALREADY_SUBMITTED', message: 'Analysis token already consumed.' });
  }

  const auditEntry = memoryStore.addAuditEntry({
    eventType: 'SUBMISSION_VALIDATED',
    analysisId: stored.analysisId,
    destinationId: stored.destinationId,
    destinationName: DESTINATIONS[stored.destinationId].name,
    taskPurposeCategory: stored.taskPurposeCategory,
    sanitizedPayloadSha256: recomputedHash,
    overallAction: stored.overallAction,
    metrics: {
      totalDetected: stored.metrics.totalDetected,
      allowedCount: stored.metrics.allowedCount,
      redactedCount: stored.metrics.redactedCount,
      blockedCount: stored.metrics.blockedCount,
    },
    decisions: stored.entities.map((e) => ({
      entityId: e.id,
      category: e.category,
      maskedToken: e.maskedValue,
      relevanceLevel: e.relevanceLevel,
      defaultDecision: e.defaultDecision,
      decision: e.decision,
      ruleId: e.policyRuleId,
    })),
  });

  return res.json({
    status: 'VALIDATED_NOT_SENT',
    action: 'EGRESS_VALIDATION_PASSED',
    analysisId: stored.analysisId,
    auditId: auditEntry.auditId,
    destinationId: stored.destinationId,
    overallAction: stored.overallAction,
    sanitizedPrompt: stored.sanitizedPrompt,
    sanitizedPayloadSha256: recomputedHash,
    timestamp: auditEntry.timestamp,
    connectorStatus: 'NO_EXTERNAL_CONNECTOR_CONFIGURED',
    note: 'Sanitized payload passed server-side destination authorization and hash verification. No external network transmission was performed because no live destination connector is configured in this prototype.',
  });
});

apiRouter.get('/api/audit', (_req: Request, res: Response) => {
  const entries = memoryStore.getAuditLog();
  return res.json({
    storagePolicy: 'In-memory ephemeral ring buffer (lost on restart). Raw prompts, raw entity values, and raw taskObjectives are excluded.',
    count: entries.length,
    entries,
  });
});

apiRouter.post('/api/evaluate', (_req: Request, res: Response) => {
  return res.json(runEvaluationBenchmark());
});
