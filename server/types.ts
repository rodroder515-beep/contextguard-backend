export type SensitivityLevel = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
export type RelevanceLevel = 'REQUIRED' | 'CONTEXTUAL' | 'EXTRANEOUS';
export type PolicyDecision = 'ALLOW' | 'REDACT' | 'BLOCK';

export type DestinationId =
  | 'external-llm'
  | 'mcp-plugin'
  | 'support-crm'
  | 'slack-bot';

export type TaskPurposeCategory =
  | 'BILLING_OPERATIONS'
  | 'CODE_REFACTORING'
  | 'CLINICAL_DOCUMENTATION'
  | 'STRATEGIC_VALUATION'
  | 'CREDENTIAL_ROTATION'
  | 'GENERAL_ASSISTANCE'
  | 'UNSPECIFIED';

export interface DestinationProfile {
  id: DestinationId;
  name: string;
  category: string;
  trustBoundary:
    | 'External Public API'
    | 'Untrusted Third-Party'
    | 'Scoped B2B Integration'
    | 'Internal Shared Channel';
  retentionPolicy: string;
  maxAllowedSensitivity: SensitivityLevel;
  allowsScopedPII: boolean;
  allowsFinancials: boolean;
  description: string;
}

export interface DetectedEntity {
  id: string;
  value: string;
  maskedValue?: string;
  category:
    | 'API_CREDENTIAL'
    | 'NATIONAL_ID'
    | 'PII_CONTACT'
    | 'CLINICAL_IDENTIFIER'
    | 'PROPRIETARY_CODENAME'
    | 'FINANCIAL_RECORD'
    | 'INFRASTRUCTURE_URI';
  label: string;
  sensitivity: SensitivityLevel;
  relevanceScore: number; // 0 to 100
  relevanceLevel: RelevanceLevel;
  relevanceRationale: string;
  defaultDecision: PolicyDecision;
  decision: PolicyDecision;
  redactedPlaceholder: string;
  policyRuleId: string;
  explanation: string;
}

export interface WorkflowScenario {
  id: string;
  title: string;
  kicker: string;
  taskObjective: string;
  defaultDestinationId: DestinationId;
  rawPrompt: string;
  architectureStageFocus: string;
}

export interface EvaluationResult {
  rawPrompt: string;
  taskObjective: string;
  destination: DestinationProfile;
  entities: DetectedEntity[];
  sanitizedPrompt: string;
  overallAction: 'TRANSMIT_SANITIZED' | 'TRANSMIT_AS_IS' | 'HALT_OUTBOUND';
  metrics: {
    totalDetected: number;
    allowedCount: number;
    redactedCount: number;
    blockedCount: number;
    scopedRelevancePct: number;
  };
  principleTriggered: boolean;
  principleSummary: string;
}

/**
 * Safe stored representation of a detected entity that excludes the raw sensitive `value`.
 */
export interface StoredEntityMetadata {
  id: string;
  maskedValue: string;
  category: DetectedEntity['category'];
  label: string;
  sensitivity: SensitivityLevel;
  relevanceScore: number;
  relevanceLevel: RelevanceLevel;
  defaultDecision: PolicyDecision;
  decision: PolicyDecision;
  redactedPlaceholder: string;
  policyRuleId: string;
}

export interface AnalyzeResponse extends EvaluationResult {
  analysisId: string;
  expiresAt: string;
  canSubmit: boolean;
  sanitizedPayloadSha256: string;
  taskPurposeCategory: TaskPurposeCategory;
}

export interface StoredAnalysis {
  analysisId: string;
  createdAt: number;
  expiresAt: number;
  destinationId: DestinationId;
  taskPurposeCategory: TaskPurposeCategory;
  sanitizedPrompt: string;
  sanitizedPayloadSha256: string;
  overallAction: EvaluationResult['overallAction'];
  entities: StoredEntityMetadata[];
  metrics: EvaluationResult['metrics'];
  principleTriggered: boolean;
  principleSummary: string;
  consumed: boolean;
}

export interface AuditLogEntry {
  auditId: string;
  timestamp: string;
  eventType: 'ANALYSIS_PERFORMED' | 'SUBMISSION_VALIDATED' | 'SUBMISSION_REJECTED';
  analysisId: string;
  destinationId: DestinationId;
  destinationName: string;
  taskPurposeCategory: TaskPurposeCategory;
  sanitizedPayloadSha256: string;
  overallAction: EvaluationResult['overallAction'];
  metrics: {
    totalDetected: number;
    allowedCount: number;
    redactedCount: number;
    blockedCount: number;
  };
  decisions: Array<{
    entityId: string;
    category: DetectedEntity['category'];
    maskedToken: string;
    relevanceLevel: RelevanceLevel;
    defaultDecision: PolicyDecision;
    decision: PolicyDecision;
    ruleId: string;
  }>;
}
