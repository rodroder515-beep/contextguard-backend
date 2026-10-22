import crypto from 'node:crypto';
import { DetectedEntity, StoredEntityMetadata, TaskPurposeCategory } from './types.ts';

/**
 * Masks a sensitive token so raw secrets, PII, or identifiers are never persisted in storage or audit logs.
 */
export function maskSensitiveToken(value: string): string {
  if (!value) return '[EMPTY]';
  const trimmed = value.trim();
  if (trimmed.length <= 4) return '***';
  if (trimmed.length <= 8) return `${trimmed.slice(0, 2)}***${trimmed.slice(-1)}`;
  const prefixLen = Math.min(4, Math.floor(trimmed.length / 4));
  const suffixLen = Math.min(3, Math.floor(trimmed.length / 4));
  return `${trimmed.slice(0, prefixLen)}***${trimmed.slice(-suffixLen)}`;
}

/**
 * Strips raw `value` and verbose rationale strings from a DetectedEntity before in-memory persistence.
 */
export function toStoredEntityMetadata(entity: DetectedEntity): StoredEntityMetadata {
  return {
    id: entity.id,
    maskedValue: maskSensitiveToken(entity.value),
    category: entity.category,
    label: entity.label,
    sensitivity: entity.sensitivity,
    relevanceScore: entity.relevanceScore,
    relevanceLevel: entity.relevanceLevel,
    defaultDecision: entity.defaultDecision,
    decision: entity.decision,
    redactedPlaceholder: entity.redactedPlaceholder,
    policyRuleId: entity.policyRuleId,
  };
}

/**
 * Maps a user-supplied taskObjective to a fixed non-sensitive category so raw taskObjective
 * strings (which could contain pasted secrets) are never retained in storage or audit logs.
 */
export function classifyTaskPurpose(taskObjective: string): TaskPurposeCategory {
  const lower = (taskObjective || '').trim().toLowerCase();
  if (!lower) return 'UNSPECIFIED';
  if (lower.includes('rotate key') || lower.includes('revoke credential')) return 'CREDENTIAL_ROTATION';
  if (lower.includes('billing') || lower.includes('refund') || lower.includes('invoice') || lower.includes('charge')) return 'BILLING_OPERATIONS';
  if (lower.includes('clinical') || lower.includes('patient') || lower.includes('discharge') || lower.includes('medical') || lower.includes('chart')) return 'CLINICAL_DOCUMENTATION';
  if (lower.includes('acquisition') || lower.includes('valuation') || lower.includes('multiple') || lower.includes('revenue') || lower.includes('memo')) return 'STRATEGIC_VALUATION';
  if (lower.includes('refactor') || lower.includes('retry') || lower.includes('database') || lower.includes('code') || lower.includes('function') || lower.includes('query')) return 'CODE_REFACTORING';
  return 'GENERAL_ASSISTANCE';
}

/**
 * Computes a hex-encoded SHA-256 digest of a string payload.
 */
export function hashPayload(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two SHA-256 hex digest strings.
 */
export function safeCompareHashes(hashA: string, hashB: string): boolean {
  if (typeof hashA !== 'string' || typeof hashB !== 'string') return false;
  const normA = hashA.trim().toLowerCase();
  const normB = hashB.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normA) || !/^[0-9a-f]{64}$/.test(normB)) return false;
  return crypto.timingSafeEqual(Buffer.from(normA, 'utf8'), Buffer.from(normB, 'utf8'));
}

/**
 * Generates a cryptographically random ID with a namespace prefix.
 */
export function generateSecureId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

/**
 * Checks whether a value is a strict plain object (`{}`), rejecting arrays, null, and custom prototypes.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}
