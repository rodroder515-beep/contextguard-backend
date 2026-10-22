import { StoredAnalysis, AuditLogEntry } from './types.ts';
import { generateSecureId } from './security.ts';

const DEFAULT_TTL_MS = 5 * 60 * 1000;
const MAX_AUDIT_ENTRIES = 200;
const MAX_ACTIVE_ANALYSES = 500;

export type InspectResult =
  | { status: 'NOT_FOUND' }
  | { status: 'EXPIRED' }
  | { status: 'ALREADY_CONSUMED'; analysis: StoredAnalysis }
  | { status: 'AVAILABLE'; analysis: StoredAnalysis };

class MemoryStore {
  private analyses = new Map<string, StoredAnalysis>();
  private auditLog: AuditLogEntry[] = [];

  private getConfiguredTtlMs(): number {
    const envTtl = Number(process.env.ANALYSIS_TTL_MS);
    return Number.isFinite(envTtl) && envTtl > 0 ? envTtl : DEFAULT_TTL_MS;
  }

  saveAnalysis(
    record: Omit<StoredAnalysis, 'analysisId' | 'createdAt' | 'expiresAt' | 'consumed'>,
    ttlMs?: number
  ): StoredAnalysis {
    this.cleanupExpired();
    if (this.analyses.size >= MAX_ACTIVE_ANALYSES) {
      const oldestKey = this.analyses.keys().next().value;
      if (oldestKey) this.analyses.delete(oldestKey);
    }

    const now = Date.now();
    const effectiveTtl = ttlMs !== undefined ? ttlMs : this.getConfiguredTtlMs();
    const stored: StoredAnalysis = {
      ...record,
      entities: record.entities.map((e) => ({ ...e })),
      metrics: { ...record.metrics },
      analysisId: generateSecureId('cg_anl'),
      createdAt: now,
      expiresAt: now + effectiveTtl,
      consumed: false,
    };
    this.analyses.set(stored.analysisId, stored);
    return stored;
  }

  inspectAnalysis(analysisId: string): InspectResult {
    const analysis = this.analyses.get(analysisId);
    if (!analysis) return { status: 'NOT_FOUND' };
    if (Date.now() > analysis.expiresAt) {
      this.analyses.delete(analysisId);
      return { status: 'EXPIRED' };
    }
    if (analysis.consumed) return { status: 'ALREADY_CONSUMED', analysis };
    return { status: 'AVAILABLE', analysis };
  }

  consumeAnalysisAtomically(analysisId: string): boolean {
    const analysis = this.analyses.get(analysisId);
    if (!analysis || Date.now() > analysis.expiresAt || analysis.consumed) {
      return false;
    }
    analysis.consumed = true;
    return true;
  }

  addAuditEntry(entry: Omit<AuditLogEntry, 'auditId' | 'timestamp'>): AuditLogEntry {
    const fullEntry: AuditLogEntry = {
      ...entry,
      auditId: generateSecureId('cg_aud'),
      timestamp: new Date().toISOString(),
    };
    this.auditLog.unshift(fullEntry);
    if (this.auditLog.length > MAX_AUDIT_ENTRIES) {
      this.auditLog.length = MAX_AUDIT_ENTRIES;
    }
    return fullEntry;
  }

  getAuditLog(): AuditLogEntry[] {
    return [...this.auditLog];
  }

  getStats() {
    this.cleanupExpired();
    return {
      activeAnalyses: this.analyses.size,
      auditEntries: this.auditLog.length,
      storageType: 'in-memory',
      persistence: 'ephemeral_lost_on_restart',
      ttlMs: this.getConfiguredTtlMs(),
    };
  }

  /** Test-only hook: mutates a stored record directly to simulate tampering/expiry. */
  tamperForTesting(analysisId: string, fn: (record: StoredAnalysis) => void): void {
    const rec = this.analyses.get(analysisId);
    if (rec) fn(rec);
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [id, item] of this.analyses.entries()) {
      if (now > item.expiresAt) this.analyses.delete(id);
    }
  }

  reset(): void {
    this.analyses.clear();
    this.auditLog = [];
  }
}

export const memoryStore = new MemoryStore();
