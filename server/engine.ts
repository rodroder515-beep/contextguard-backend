import {
  DestinationId,
  DestinationProfile,
  DetectedEntity,
  EvaluationResult,
  PolicyDecision,
  RelevanceLevel,
  SensitivityLevel,
  TaskPurposeCategory,
  WorkflowScenario,
} from './types.ts';
import { classifyTaskPurpose, maskSensitiveToken } from './security.ts';

export const DESTINATIONS: Record<DestinationId, DestinationProfile> = {
  'external-llm': {
    id: 'external-llm',
    name: 'External Frontier LLM API',
    category: 'Model Inference Endpoint',
    trustBoundary: 'External Public API',
    retentionPolicy: 'Zero-data-retention API tier; external cloud boundary',
    maxAllowedSensitivity: 'MODERATE',
    allowsScopedPII: false,
    allowsFinancials: true,
    description:
      'Permits task-essential business metrics and code structure, but requires structure-preserving redaction for PII and strictly blocks raw credentials or regulated IDs.',
  },
  'mcp-plugin': {
    id: 'mcp-plugin',
    name: 'Untrusted Community MCP Server',
    category: 'External Tool / Plugin',
    trustBoundary: 'Untrusted Third-Party',
    retentionPolicy: 'Unverified third-party tool logging',
    maxAllowedSensitivity: 'LOW',
    allowsScopedPII: false,
    allowsFinancials: false,
    description:
      'Enforces strict least-privilege authorization. Even when sensitive entities are highly relevant to the task, raw PII, financials, and proprietary codenames are redacted or blocked.',
  },
  'support-crm': {
    id: 'support-crm',
    name: 'Authorized Support CRM Gateway',
    category: 'Scoped Enterprise Tool',
    trustBoundary: 'Scoped B2B Integration',
    retentionPolicy: 'SOC2 / BAA-scoped tenant storage',
    maxAllowedSensitivity: 'HIGH',
    allowsScopedPII: true,
    allowsFinancials: true,
    description:
      'Authorized to receive task-relevant customer contact details and invoice figures for ticketing workflows, while blocking extraneous secrets and national IDs.',
  },
  'slack-bot': {
    id: 'slack-bot',
    name: 'Workspace Triage Webhook',
    category: 'Internal Multi-User Channel',
    trustBoundary: 'Internal Shared Channel',
    retentionPolicy: '90-day workspace message retention',
    maxAllowedSensitivity: 'MODERATE',
    allowsScopedPII: false,
    allowsFinancials: false,
    description:
      'Prevents lateral internal oversharing by masking customer PII and unannounced financial records before posting summaries to broad channels.',
  },
};

export const WORKFLOW_SCENARIOS: WorkflowScenario[] = [
  {
    id: 'billing-triage',
    title: 'Customer Billing Triage',
    kicker: 'SCENARIO 01 · SUPPORT AGENT',
    taskObjective: 'Draft a billing refund confirmation email for invoice amount and customer contact',
    defaultDestinationId: 'external-llm',
    rawPrompt:
      'Context dump from support session: Customer Elena Rostova (elena.rostova@acme-bio.io) requested a duplicate-charge refund of $1,420.00 on Invoice #INV-9042. Internal debug env had Stripe key sk_live_98a7f65c44b2109d and verification SSN 419-00-8821 attached in thread logs. Draft a polite refund confirmation reply.',
    architectureStageFocus: 'Separating incidental thread credentials from task-essential billing context.',
  },
  {
    id: 'code-refactor',
    title: 'Repository Context Assistant',
    kicker: 'SCENARIO 02 · CODING AGENT',
    taskObjective: 'Optimize retry backoff logic in database connection helper',
    defaultDestinationId: 'mcp-plugin',
    rawPrompt:
      'Refactor the exponential backoff retry loop in our connection helper. Note from local .env: postgres://admin_prod:Kx99vL2pQ@db-prod-east.internal:5432/ledger and AWS key AKIAIOSFODNN7EXAMPLE. Ensure the TypeScript function retries 3 times with jitter before throwing.',
    architectureStageFocus: 'Preventing local .env credentials ingested by coding agents from leaking to external MCP tools.',
  },
  {
    id: 'clinical-summary',
    title: 'Clinical Discharge Synthesis',
    kicker: 'SCENARIO 03 · HEALTHCARE WORKFLOW',
    taskObjective: 'Translate post-operative mobility instructions into plain patient language',
    defaultDestinationId: 'external-llm',
    rawPrompt:
      'Patient record MRN-88412-B (Marcus Vance, contact marcus.v@healthmail.org, SSN 502-11-3940). Discharge note: Elevate right knee for 48 hours, apply cold pack 20 mins every 3 hours, and schedule follow-up physical therapy in 10 days. Rewrite instructions at a 6th-grade reading level.',
    architectureStageFocus: 'Preserving clinical instruction semantics while stripping HIPAA identifiers.',
  },
  {
    id: 'ma-briefing',
    title: 'Strategic M&A Briefing',
    kicker: 'SCENARIO 04 · EXECUTIVE ANALYST',
    taskObjective: 'Summarize Q4 revenue multiple and valuation metrics for acquisition memo',
    defaultDestinationId: 'mcp-plugin',
    rawPrompt:
      'Evaluate Project Helios confidential acquisition target with Q4 unannounced revenue of $48.2M and contact lead d.chen@helios-semi.com. Compare against public semiconductor SaaS multiples using external market search tool.',
    architectureStageFocus: 'Demonstrating that high task relevance ($48.2M & Project Helios) does not grant permission to share with an untrusted external search plugin.',
  },
];

export interface PatternSpec {
  category: DetectedEntity['category'];
  label: string;
  sensitivity: SensitivityLevel;
  regex: RegExp;
  placeholderPrefix: string;
  relevantKeywords: string[];
  contextualKeywords: string[];
}

export const ENTITY_PATTERNS: PatternSpec[] = [
  {
    category: 'API_CREDENTIAL',
    label: 'Live API Secret / Access Key',
    sensitivity: 'CRITICAL',
    regex: /\b(?:sk_live_[a-zA-Z0-9]{10,}|AKIA[A-Z0-9]{12,}|ghp_[a-zA-Z0-9]{16,})\b/g,
    placeholderPrefix: 'REDACTED_CREDENTIAL',
    relevantKeywords: ['rotate key', 'revoke credential'],
    contextualKeywords: ['auth', 'key'],
  },
  {
    category: 'INFRASTRUCTURE_URI',
    label: 'Database Connection String',
    sensitivity: 'CRITICAL',
    regex: /\b(?:postgres|mongodb|mysql|redis):\/\/[^\s,;)]+/gi,
    placeholderPrefix: 'REDACTED_DB_URI',
    relevantKeywords: ['parse uri', 'connection string format'],
    contextualKeywords: ['database', 'connection', 'retry'],
  },
  {
    category: 'NATIONAL_ID',
    label: 'Government / Social Security ID',
    sensitivity: 'CRITICAL',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    placeholderPrefix: 'REDACTED_NATIONAL_ID',
    relevantKeywords: ['tax filing', 'identity verification'],
    contextualKeywords: ['verify', 'record'],
  },
  {
    category: 'CLINICAL_IDENTIFIER',
    label: 'Medical Record Number (MRN)',
    sensitivity: 'HIGH',
    regex: /\bMRN-\d{4,6}-[A-Z0-9]\b/g,
    placeholderPrefix: 'PATIENT_MRN_TOKEN',
    relevantKeywords: ['patient record lookup', 'chart indexing'],
    contextualKeywords: ['clinical', 'discharge', 'patient', 'medical'],
  },
  {
    category: 'PROPRIETARY_CODENAME',
    label: 'Confidential Initiative Codename',
    sensitivity: 'HIGH',
    regex: /\bProject\s+(?:Helios|Obsidian|Titan|Aegis|Vanguard)\b/g,
    placeholderPrefix: 'TARGET_ENTITY_ALIAS',
    relevantKeywords: ['acquisition', 'memo', 'valuation', 'target', 'strategy'],
    contextualKeywords: ['project', 'summary', 'evaluate'],
  },
  {
    category: 'PII_CONTACT',
    label: 'Personal Email Identifier',
    sensitivity: 'MODERATE',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    placeholderPrefix: 'CONTACT_EMAIL',
    relevantKeywords: ['contact', 'email', 'reply', 'send', 'customer', 'billing'],
    contextualKeywords: ['support', 'thread', 'lead', 'patient'],
  },
  {
    category: 'FINANCIAL_RECORD',
    label: 'Monetary / Revenue Figure',
    sensitivity: 'HIGH',
    regex: /\$[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?[MBK]?\b/g,
    placeholderPrefix: 'SCOPED_AMOUNT',
    relevantKeywords: ['invoice', 'refund', 'billing', 'revenue', 'valuation', 'amount', 'multiple', 'charge'],
    contextualKeywords: ['financial', 'summary', 'q4', 'memo'],
  },
];

const DECISION_SEVERITY_RANK: Record<PolicyDecision, number> = {
  ALLOW: 0,
  REDACT: 1,
  BLOCK: 2,
};

/**
 * Resolves the effective decision by ensuring overrides can ONLY tighten policy
 * (`ALLOW -> REDACT/BLOCK` or `REDACT -> BLOCK`) and can NEVER weaken server-mandated decisions.
 */
export function resolveAuthoritativeDecision(
  serverDefaultDecision: PolicyDecision,
  requestedOverride?: PolicyDecision
): PolicyDecision {
  if (!requestedOverride) return serverDefaultDecision;
  if (DECISION_SEVERITY_RANK[requestedOverride] <= DECISION_SEVERITY_RANK[serverDefaultDecision]) {
    return serverDefaultDecision;
  }
  return requestedOverride;
}

export function computeRelevance(
  spec: PatternSpec,
  value: string,
  taskObjective: string
): { score: number; level: RelevanceLevel; rationale: string } {
  const lowerObj = (taskObjective || '').toLowerCase();

  const matchedRequired = spec.relevantKeywords.some((kw) => lowerObj.includes(kw));
  const matchedContextual = spec.contextualKeywords.some((kw) => lowerObj.includes(kw));

  if (spec.category === 'API_CREDENTIAL') {
    if (matchedRequired) {
      return {
        score: 92,
        level: 'REQUIRED',
        rationale: `Directly referenced by "${taskObjective}" (high task utility), yet remains subject to strict destination credential denial.`,
      };
    }
    return {
      score: 4,
      level: 'EXTRANEOUS',
      rationale: `Raw secret "${value.slice(0, 10)}..." is incidental context bloat; zero semantic utility for "${taskObjective}".`,
    };
  }

  if (spec.category === 'INFRASTRUCTURE_URI') {
    if (matchedRequired) {
      return {
        score: 88,
        level: 'REQUIRED',
        rationale: `Connection URI structure is referenced by "${taskObjective}", but embedded credentials cannot cross the external boundary.`,
      };
    }
    return {
      score: 12,
      level: 'EXTRANEOUS',
      rationale: 'Embedded credentials in URI are unnecessary for refactoring retry backoff control flow.',
    };
  }

  if (spec.category === 'NATIONAL_ID') {
    return {
      score: 6,
      level: 'EXTRANEOUS',
      rationale: `National identifier "${value}" is unrelated to fulfilling "${taskObjective}".`,
    };
  }

  if (matchedRequired) {
    const score = spec.category === 'FINANCIAL_RECORD' ? 94 : spec.category === 'PROPRIETARY_CODENAME' ? 89 : 86;
    return {
      score,
      level: 'REQUIRED',
      rationale: `Directly referenced by task goal ("${taskObjective}"). High semantic utility for reasoning.`,
    };
  }

  if (matchedContextual) {
    return {
      score: 52,
      level: 'CONTEXTUAL',
      rationale: 'Provides background context for the workflow, though a synthetic token can preserve coherence.',
    };
  }

  return {
    score: 18,
    level: 'EXTRANEOUS',
    rationale: `Present in the context window but not required to execute "${taskObjective}".`,
  };
}

export function determinePolicyDecision(
  category: DetectedEntity['category'],
  _sensitivity: SensitivityLevel,
  relevanceLevel: RelevanceLevel,
  destination: DestinationProfile
): { decision: PolicyDecision; ruleId: string; explanation: string } {
  if (category === 'API_CREDENTIAL' || category === 'INFRASTRUCTURE_URI') {
    return {
      decision: 'BLOCK',
      ruleId: 'CG-POL-001 (Zero-Credential-Egress)',
      explanation: `Blocked: Production credentials and authenticated connection URIs cannot exit to ${destination.name} (${destination.trustBoundary}) under any task relevance score.`,
    };
  }

  if (category === 'NATIONAL_ID') {
    return {
      decision: 'BLOCK',
      ruleId: 'CG-POL-002 (Regulated-Identifier-Guard)',
      explanation: `Blocked: Government IDs carry CRITICAL sensitivity and have no authorization scope for ${destination.name}.`,
    };
  }

  if (category === 'CLINICAL_IDENTIFIER') {
    return {
      decision: 'REDACT',
      ruleId: 'CG-POL-014 (HIPAA-Safe-Deidentification)',
      explanation: `Redacted: Even in clinical summarization workflows, ${destination.name} is not authorized to ingest raw Medical Record Numbers. Replaced with structure-preserving token.`,
    };
  }

  if (category === 'PROPRIETARY_CODENAME') {
    if (destination.id === 'mcp-plugin' || destination.id === 'external-llm' || destination.id === 'slack-bot') {
      return {
        decision: 'REDACT',
        ruleId: 'CG-POL-021 (Relevance-Not-Permission-MNPI)',
        explanation: `Redacted: Although "${category}" has high task relevance (${relevanceLevel}), ${destination.name} (${destination.trustBoundary}) lacks authorization for unannounced M&A codenames.`,
      };
    }
    return {
      decision: 'ALLOW',
      ruleId: 'CG-POL-022 (Scoped-Enterprise-Allow)',
      explanation: `Allowed: Task-relevant initiative identifier permitted for ${destination.name}.`,
    };
  }

  if (category === 'PII_CONTACT') {
    if (relevanceLevel === 'REQUIRED' && destination.allowsScopedPII) {
      return {
        decision: 'ALLOW',
        ruleId: 'CG-POL-030 (Scoped-CRM-PII-Allow)',
        explanation: `Allowed: Contact PII is required for the task and ${destination.name} (${destination.trustBoundary}) is explicitly authorized for customer records.`,
      };
    }
    return {
      decision: 'REDACT',
      ruleId: 'CG-POL-031 (PII-Boundary-Redaction)',
      explanation:
        relevanceLevel === 'REQUIRED'
          ? `Redacted: Contact address is relevant to drafting the response, but ${destination.name} (${destination.trustBoundary}) is not authorized for raw PII. Substituted reversible token.`
          : `Redacted: Incidental contact PII stripped before transmission to ${destination.name}.`,
    };
  }

  if (category === 'FINANCIAL_RECORD') {
    if (relevanceLevel === 'REQUIRED' && destination.allowsFinancials) {
      return {
        decision: 'ALLOW',
        ruleId: 'CG-POL-040 (Task-Scoped-Numeric-Allow)',
        explanation: `Allowed: Monetary figure is essential to the task objective and permitted under ${destination.name} policy.`,
      };
    }
    return {
      decision: 'REDACT',
      ruleId: 'CG-POL-041 (Unauthorized-Financial-Egress)',
      explanation: `Redacted: High task relevance does not grant permission to transmit financial figures to ${destination.name} (${destination.trustBoundary}). Masked with synthetic value.`,
    };
  }

  return {
    decision: 'REDACT',
    ruleId: 'CG-POL-099 (Default-Boundary-Redact)',
    explanation: `Redacted by default boundary policy for ${destination.name}.`,
  };
}

export function evaluateWorkflowContext(
  rawPrompt: string,
  taskObjective: string,
  destinationId: DestinationId,
  decisionOverrides?: Record<string, PolicyDecision>
): EvaluationResult {
  const destination = DESTINATIONS[destinationId] || DESTINATIONS['external-llm'];
  const entities: DetectedEntity[] = [];
  const seenValues = new Set<string>();
  const matchedRanges: Array<[number, number]> = [];

  let indexCounter = 1;

  for (const spec of ENTITY_PATTERNS) {
    const matches = rawPrompt.matchAll(spec.regex);
    for (const match of matches) {
      const value = match[0];
      const start = match.index ?? 0;
      const end = start + value.length;
      const overlaps = matchedRanges.some(([rStart, rEnd]) => start < rEnd && end > rStart);
      if (seenValues.has(value) || overlaps) continue;
      seenValues.add(value);
      matchedRanges.push([start, end]);

      const id = `entity-${indexCounter}`;
      const relevance = computeRelevance(spec, value, taskObjective);
      const policy = determinePolicyDecision(
        spec.category,
        spec.sensitivity,
        relevance.level,
        destination
      );

      const placeholder = `<${spec.placeholderPrefix}_${indexCounter}>`;
      // Overrides can only tighten the server-mandated decision, never weaken it.
      const requestedOverride = Object.prototype.hasOwnProperty.call(decisionOverrides ?? {}, id)
        ? decisionOverrides?.[id]
        : undefined;
      const effectiveDecision: PolicyDecision = resolveAuthoritativeDecision(policy.decision, requestedOverride);

      entities.push({
        id,
        value,
        category: spec.category,
        label: spec.label,
        sensitivity: spec.sensitivity,
        relevanceScore: relevance.score,
        relevanceLevel: relevance.level,
        relevanceRationale: relevance.rationale,
        defaultDecision: policy.decision,
        decision: effectiveDecision,
        redactedPlaceholder: placeholder,
        policyRuleId: policy.ruleId,
        explanation: policy.explanation,
      });

      indexCounter++;
    }
  }

  let sanitizedPrompt = rawPrompt;
  for (const entity of entities) {
    if (entity.decision === 'REDACT') {
      sanitizedPrompt = sanitizedPrompt.split(entity.value).join(entity.redactedPlaceholder);
    } else if (entity.decision === 'BLOCK') {
      sanitizedPrompt = sanitizedPrompt.split(entity.value).join(`[BLOCKED:${entity.category}]`);
    }
  }

  const allowedCount = entities.filter((e) => e.decision === 'ALLOW').length;
  const redactedCount = entities.filter((e) => e.decision === 'REDACT').length;
  const blockedCount = entities.filter((e) => e.decision === 'BLOCK').length;

  const relevantEntities = entities.filter((e) => e.relevanceLevel === 'REQUIRED' || e.relevanceLevel === 'CONTEXTUAL');
  const scopedRelevancePct =
    entities.length > 0 ? Math.round((relevantEntities.length / entities.length) * 100) : 100;

  const relevanceOverriddenByAuth = entities.some(
    (e) =>
      (e.relevanceLevel === 'REQUIRED' || e.relevanceLevel === 'CONTEXTUAL') &&
      (e.decision === 'REDACT' || e.decision === 'BLOCK')
  );

  const overallAction: EvaluationResult['overallAction'] =
    blockedCount > 0
      ? 'HALT_OUTBOUND'
      : redactedCount > 0
      ? 'TRANSMIT_SANITIZED'
      : 'TRANSMIT_AS_IS';

  const principleSummary = relevanceOverriddenByAuth
    ? `Core Principle Active: ${
        entities.filter(
          (e) =>
            (e.relevanceLevel === 'REQUIRED' || e.relevanceLevel === 'CONTEXTUAL') &&
            e.decision !== 'ALLOW'
        ).length
      } task-relevant sensitive item(s) were withheld or redacted because ${destination.name} lacks authorization scope.`
    : blockedCount > 0
    ? 'Extraneous high-risk credentials blocked before leaving the workflow boundary.'
    : `All task-relevant entities satisfy ${destination.name} authorization constraints.`;

  return {
    rawPrompt,
    taskObjective,
    destination,
    entities,
    sanitizedPrompt,
    overallAction,
    metrics: {
      totalDetected: entities.length,
      allowedCount,
      redactedCount,
      blockedCount,
      scopedRelevancePct,
    },
    principleTriggered: relevanceOverriddenByAuth,
    principleSummary,
  };
}

export interface ServerEvaluationOutput extends EvaluationResult {
  taskPurposeCategory: TaskPurposeCategory;
}

/**
 * Runs the authoritative ContextGuard evaluation on the server, enforcing non-weakening overrides.
 */
export function evaluateWorkflowContextServer(
  rawPrompt: string,
  taskObjective: string,
  destinationId: DestinationId,
  decisionOverrides?: Record<string, PolicyDecision>
): { result: ServerEvaluationOutput; unknownOverrideIds: string[] } {
  const cleanObjective = (taskObjective || '').trim();
  const baseEvaluation = evaluateWorkflowContext(rawPrompt, cleanObjective, destinationId);

  const safeOverrides: Record<string, PolicyDecision> = {};
  const unknownOverrideIds: string[] = [];

  if (decisionOverrides) {
    const baseEntityMap = new Map(baseEvaluation.entities.map((e) => [e.id, e]));
    for (const [key, requestedDecision] of Object.entries(decisionOverrides)) {
      const targetEntity = baseEntityMap.get(key);
      if (!targetEntity) {
        unknownOverrideIds.push(key);
        continue;
      }
      const effective = resolveAuthoritativeDecision(targetEntity.defaultDecision, requestedDecision);
      if (effective !== targetEntity.defaultDecision) {
        safeOverrides[key] = effective;
      }
    }
  }

  const finalEval =
    Object.keys(safeOverrides).length > 0
      ? evaluateWorkflowContext(rawPrompt, cleanObjective, destinationId, safeOverrides)
      : baseEvaluation;

  return {
    unknownOverrideIds,
    result: {
      ...finalEval,
      taskPurposeCategory: classifyTaskPurpose(cleanObjective),
      entities: finalEval.entities.map((e) => ({
        ...e,
        maskedValue: maskSensitiveToken(e.value),
      })),
    },
  };
}
