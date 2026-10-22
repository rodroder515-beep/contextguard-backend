import { DestinationId, DetectedEntity, PolicyDecision } from './types.ts';

export interface SyntheticCase {
  id: string;
  category: string;
  destinationId: DestinationId;
  taskObjective: string;
  rawPrompt: string;
  expectedAction: 'TRANSMIT_SANITIZED' | 'TRANSMIT_AS_IS' | 'HALT_OUTBOUND';
  expectedEntities: Array<{
    value: string;
    category: DetectedEntity['category'];
    expectedDecision: PolicyDecision;
  }>;
}

export const SYNTHETIC_EVALUATION_CASES: SyntheticCase[] = [
  {
    id: 'TC-01', category: 'credentials', destinationId: 'external-llm',
    taskObjective: 'Draft a billing refund confirmation email for invoice amount and customer contact',
    rawPrompt: 'Customer elena.rostova@acme-bio.io requested a refund of $1,420.00. Debug env had sk_live_98a7f65c44b2109d and SSN 419-00-8821.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'sk_live_98a7f65c44b2109d', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
      { value: '419-00-8821', category: 'NATIONAL_ID', expectedDecision: 'BLOCK' },
      { value: 'elena.rostova@acme-bio.io', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
      { value: '$1,420.00', category: 'FINANCIAL_RECORD', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-02', category: 'credentials', destinationId: 'mcp-plugin',
    taskObjective: 'Optimize retry backoff logic in database connection helper',
    rawPrompt: 'Refactor retry loop. Env: postgres://admin_prod:Kx99vL2pQ@db-prod-east.internal:5432/ledger and AKIAIOSFODNN7EXAMPLE.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'AKIAIOSFODNN7EXAMPLE', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
      { value: 'postgres://admin_prod:Kx99vL2pQ@db-prod-east.internal:5432/ledger', category: 'INFRASTRUCTURE_URI', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-03', category: 'clinical', destinationId: 'external-llm',
    taskObjective: 'Translate post-operative mobility instructions into plain patient language',
    rawPrompt: 'Patient MRN-88412-B (contact marcus.v@healthmail.org). Elevate right knee for 48 hours.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'MRN-88412-B', category: 'CLINICAL_IDENTIFIER', expectedDecision: 'REDACT' },
      { value: 'marcus.v@healthmail.org', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-04', category: 'unauthorized-mcp', destinationId: 'mcp-plugin',
    taskObjective: 'Summarize Q4 revenue multiple and valuation metrics for acquisition memo',
    rawPrompt: 'Evaluate Project Helios acquisition target with Q4 revenue of $48.2M and lead d.chen@helios-semi.com.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'Project Helios', category: 'PROPRIETARY_CODENAME', expectedDecision: 'REDACT' },
      { value: 'd.chen@helios-semi.com', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
      { value: '$48.2M', category: 'FINANCIAL_RECORD', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-05', category: 'authorized-crm', destinationId: 'support-crm',
    taskObjective: 'Send customer billing invoice amount email to customer contact',
    rawPrompt: 'Contact customer at sarah.connor@sky-shield.com regarding invoice amount $3,450.00.',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [
      { value: 'sarah.connor@sky-shield.com', category: 'PII_CONTACT', expectedDecision: 'ALLOW' },
      { value: '$3,450.00', category: 'FINANCIAL_RECORD', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-06', category: 'authorized-crm', destinationId: 'support-crm',
    taskObjective: 'Update billing ticket for customer contact email and amount',
    rawPrompt: 'Customer john.doe@corp.net verified payment of $250.00. Token: sk_live_9998887776665554.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'sk_live_9998887776665554', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
      { value: 'john.doe@corp.net', category: 'PII_CONTACT', expectedDecision: 'ALLOW' },
      { value: '$250.00', category: 'FINANCIAL_RECORD', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-07', category: 'authorized-crm', destinationId: 'support-crm',
    taskObjective: 'Assign support ticket to strategic target Project Aegis contact',
    rawPrompt: 'Ticket for Project Aegis partner escalation lead dev.ops@partner.org.',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [
      { value: 'Project Aegis', category: 'PROPRIETARY_CODENAME', expectedDecision: 'ALLOW' },
      { value: 'dev.ops@partner.org', category: 'PII_CONTACT', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-08', category: 'authorized-crm', destinationId: 'support-crm',
    taskObjective: 'Verify customer contact details for ticketing',
    rawPrompt: 'Customer alex.miller@fastmail.com provided SSN 987-65-4321.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: '987-65-4321', category: 'NATIONAL_ID', expectedDecision: 'BLOCK' },
      { value: 'alex.miller@fastmail.com', category: 'PII_CONTACT', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-09', category: 'slack-triage', destinationId: 'slack-bot',
    taskObjective: 'Post outage notice to workspace triage channel for customer contact',
    rawPrompt: 'Outage reported by alice.wong@fintech.io on gateway #4.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'alice.wong@fintech.io', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-10', category: 'slack-triage', destinationId: 'slack-bot',
    taskObjective: 'Summarize acquisition valuation revenue update for engineering sync',
    rawPrompt: 'Update on Project Titan acquisition: closed initial round at $12.5M.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'Project Titan', category: 'PROPRIETARY_CODENAME', expectedDecision: 'REDACT' },
      { value: '$12.5M', category: 'FINANCIAL_RECORD', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-11', category: 'credentials', destinationId: 'slack-bot',
    taskObjective: 'Announce release branch status in workspace triage',
    rawPrompt: 'Branch release-v2 failed. CI token: ghp_112233445566778899aabbcc.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'ghp_112233445566778899aabbcc', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-12', category: 'credentials', destinationId: 'slack-bot',
    taskObjective: 'Report database pool saturation alert to Slack',
    rawPrompt: 'Pool exhaustion on mongodb://srv_user:SecretPass99@mongo.internal:27017/analytics',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'mongodb://srv_user:SecretPass99@mongo.internal:27017/analytics', category: 'INFRASTRUCTURE_URI', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-13', category: 'credentials', destinationId: 'external-llm',
    taskObjective: 'rotate key and revoke credential immediately',
    rawPrompt: 'Rotate compromised key sk_live_98a7f65c44b2109d immediately',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'sk_live_98a7f65c44b2109d', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-14', category: 'credentials', destinationId: 'external-llm',
    taskObjective: 'Review S3 upload helper function for race condition',
    rawPrompt: 'const key = "AKIAIOSFODNN7EXAMPLE"; s3.upload({ Bucket: "assets" });',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'AKIAIOSFODNN7EXAMPLE', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-15', category: 'national-id', destinationId: 'external-llm',
    taskObjective: 'Evaluate loan invoice amount amortization schedule',
    rawPrompt: 'Applicant SSN 123-45-6789, requested loan amount $25,000.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: '123-45-6789', category: 'NATIONAL_ID', expectedDecision: 'BLOCK' },
      { value: '$25,000', category: 'FINANCIAL_RECORD', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-16', category: 'credentials', destinationId: 'mcp-plugin',
    taskObjective: 'parse uri connection string format for Redis cluster',
    rawPrompt: 'Cache config at redis://default:SuperSecr3tToken@cache-cluster.internal:6379/0',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'redis://default:SuperSecr3tToken@cache-cluster.internal:6379/0', category: 'INFRASTRUCTURE_URI', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-17', category: 'clinical', destinationId: 'external-llm',
    taskObjective: 'patient record lookup and chart indexing summary',
    rawPrompt: 'Cohort review: MRN-10293-A and MRN-44912-C showed 80% recovery.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'MRN-10293-A', category: 'CLINICAL_IDENTIFIER', expectedDecision: 'REDACT' },
      { value: 'MRN-44912-C', category: 'CLINICAL_IDENTIFIER', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-18', category: 'clinical', destinationId: 'mcp-plugin',
    taskObjective: 'Send follow-up email reminder to patient contact',
    rawPrompt: 'Patient MRN-9901-X, contact karen.b@carenet.org.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'MRN-9901-X', category: 'CLINICAL_IDENTIFIER', expectedDecision: 'REDACT' },
      { value: 'karen.b@carenet.org', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-19', category: 'clinical', destinationId: 'external-llm',
    taskObjective: 'Format clinical discharge notes for chart indexing',
    rawPrompt: 'Patient chart MRN-50112-D, SSN 333-22-1111. Cleared for discharge.',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: '333-22-1111', category: 'NATIONAL_ID', expectedDecision: 'BLOCK' },
      { value: 'MRN-50112-D', category: 'CLINICAL_IDENTIFIER', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-20', category: 'benign', destinationId: 'external-llm',
    taskObjective: 'Explain dosage guidelines for amoxicillin',
    rawPrompt: 'What is the standard pediatric dosage guideline for amoxicillin?',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [],
  },
  {
    id: 'TC-21', category: 'financial', destinationId: 'external-llm',
    taskObjective: 'Calculate annual recurring revenue run rate from invoice amount',
    rawPrompt: 'Monthly billing run rate is $120,000. Project 12-month ARR.',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [
      { value: '$120,000', category: 'FINANCIAL_RECORD', expectedDecision: 'ALLOW' },
    ],
  },
  {
    id: 'TC-22', category: 'unauthorized-mcp', destinationId: 'mcp-plugin',
    taskObjective: 'Format quarterly revenue table for valuation report',
    rawPrompt: 'Q1 had revenue of $4.5M, Q2 reached $5.8M.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: '$4.5M', category: 'FINANCIAL_RECORD', expectedDecision: 'REDACT' },
      { value: '$5.8M', category: 'FINANCIAL_RECORD', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-23', category: 'unauthorized-mcp', destinationId: 'external-llm',
    taskObjective: 'Draft strategic market analysis for Project Vanguard acquisition memo',
    rawPrompt: 'Analyze semiconductor market position for Project Vanguard acquisition.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'Project Vanguard', category: 'PROPRIETARY_CODENAME', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-24', category: 'unauthorized-mcp', destinationId: 'mcp-plugin',
    taskObjective: 'Find market multiples for Project Obsidian valuation with $19.4M revenue',
    rawPrompt: 'Search public comps for Project Obsidian with current revenue $19.4M.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'Project Obsidian', category: 'PROPRIETARY_CODENAME', expectedDecision: 'REDACT' },
      { value: '$19.4M', category: 'FINANCIAL_RECORD', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-25', category: 'missing-purpose', destinationId: 'external-llm',
    taskObjective: '',
    rawPrompt: 'Context: d.smith@company.com paid $800.00 for license renewal.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'd.smith@company.com', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
      { value: '$800.00', category: 'FINANCIAL_RECORD', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-26', category: 'irrelevant-pii', destinationId: 'external-llm',
    taskObjective: 'Format python function with PEP8 spacing rules',
    rawPrompt: 'Format helper. Author: dev.tester@legacy-domain.org. def foo(x): return x * 2',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'dev.tester@legacy-domain.org', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-27', category: 'ambiguous', destinationId: 'external-llm',
    taskObjective: 'Help me with this context',
    rawPrompt: 'Can you check sk_live_1234567890abcdef for proper format?',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'sk_live_1234567890abcdef', category: 'API_CREDENTIAL', expectedDecision: 'BLOCK' },
    ],
  },
  {
    id: 'TC-28', category: 'irrelevant-pii', destinationId: 'external-llm',
    taskObjective: 'Extract error stack trace and root cause exception message',
    rawPrompt: 'Error at user_auth(). Logs: admin.ops@bank.net and cto.lead@hq.com.',
    expectedAction: 'TRANSMIT_SANITIZED',
    expectedEntities: [
      { value: 'admin.ops@bank.net', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
      { value: 'cto.lead@hq.com', category: 'PII_CONTACT', expectedDecision: 'REDACT' },
    ],
  },
  {
    id: 'TC-29', category: 'benign', destinationId: 'external-llm',
    taskObjective: 'Explain time complexity of binary search',
    rawPrompt: 'Explain how binary search achieves O(log n) time complexity.',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [],
  },
  {
    id: 'TC-30', category: 'benign', destinationId: 'mcp-plugin',
    taskObjective: 'Write PostgreSQL query with window function',
    rawPrompt: 'Write a query computing employee rank partitioned by department_id.',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [],
  },
  {
    id: 'TC-31', category: 'benign', destinationId: 'support-crm',
    taskObjective: 'Draft reusable greeting template',
    rawPrompt: 'Draft a greeting template using {{first_name}} and {{ticket_id}}.',
    expectedAction: 'TRANSMIT_AS_IS',
    expectedEntities: [],
  },
  {
    id: 'TC-32', category: 'credentials', destinationId: 'external-llm',
    taskObjective: 'Explain how to configure SSL on MySQL connection helper',
    rawPrompt: 'Dev URI: mysql://app_user:PlainTextPwd456@db-master.dev:3306/primary',
    expectedAction: 'HALT_OUTBOUND',
    expectedEntities: [
      { value: 'mysql://app_user:PlainTextPwd456@db-master.dev:3306/primary', category: 'INFRASTRUCTURE_URI', expectedDecision: 'BLOCK' },
    ],
  },
];
