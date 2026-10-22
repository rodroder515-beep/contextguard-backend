process.env.NODE_ENV = 'test';

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SYNTHETIC_EVALUATION_CASES,
  runEvaluationBenchmark,
} from '../evaluationSuite.ts';
import { evaluateWorkflowContext, WORKFLOW_SCENARIOS } from '../engine.ts';

test('1. Dataset contains 32 synthetic cases with explicit entity-level ground-truth labels', () => {
  assert.equal(SYNTHETIC_EVALUATION_CASES.length, 32);
  for (const tc of SYNTHETIC_EVALUATION_CASES) {
    assert.ok(Array.isArray(tc.expectedEntities));
  }
});

test('2. Benchmark metrics match mathematical totals aggregated from caseResults', () => {
  const report = runEvaluationBenchmark();
  assert.equal(report.totalTestCases, SYNTHETIC_EVALUATION_CASES.length);

  for (const systemKey of ['keyword_only', 'relevance_without_auth', 'context_guard'] as const) {
    const sysMetrics = report.comparison[systemKey];
    const outcomes = report.caseResults.map((c) => c.outcomes[systemKey]);

    const passedCases = outcomes.filter((o) => o.passed).length;
    const actionMatchedCases = outcomes.filter((o) => o.actionMatched).length;
    const sumDisclosures = outcomes.reduce((acc, o) => acc + o.unauthorizedDisclosures, 0);
    const sumMissed = outcomes.reduce((acc, o) => acc + o.missedDetections, 0);
    const sumOverRedactions = outcomes.reduce((acc, o) => acc + o.unnecessaryRedactions, 0);
    const sumViolations = outcomes.reduce((acc, o) => acc + o.policyViolations, 0);

    assert.equal(sysMetrics.exactCaseMatches, passedCases);
    assert.equal(sysMetrics.exactActionMatches, actionMatchedCases);
    assert.equal(sysMetrics.unauthorizedDisclosureCount, sumDisclosures);
    assert.equal(sysMetrics.missedDetectionCount, sumMissed);
    assert.equal(sysMetrics.unnecessaryRedactionCount, sumOverRedactions);
    assert.equal(sysMetrics.policyViolationCount, sumViolations);

    const expectedAccuracy = Math.round((passedCases / report.totalTestCases) * 10000) / 100;
    assert.equal(sysMetrics.accuracyPct, expectedAccuracy);
  }
});

test('3. ContextGuard outperforms Baselines A and B on actual executed test cases', () => {
  const report = runEvaluationBenchmark();
  const { keyword_only, relevance_without_auth, context_guard } = report.comparison;

  assert.ok(keyword_only.missedDetectionCount > 0);
  assert.ok(keyword_only.unnecessaryRedactionCount > 0);
  assert.ok(relevance_without_auth.unauthorizedDisclosureCount > 0);

  assert.ok(context_guard.accuracyPct > keyword_only.accuracyPct);
  assert.ok(context_guard.accuracyPct > relevance_without_auth.accuracyPct);
  assert.ok(context_guard.unauthorizedDisclosureCount < relevance_without_auth.unauthorizedDisclosureCount);
});

test('4. Policy engine detects credentials, SSNs, emails, and invoice figures in billing scenario', () => {
  const scenario = WORKFLOW_SCENARIOS[0];
  const result = evaluateWorkflowContext(scenario.rawPrompt, scenario.taskObjective, 'external-llm');
  assert.equal(result.entities.length, 4);
  const apiKey = result.entities.find((e) => e.category === 'API_CREDENTIAL');
  assert.equal(apiKey?.decision, 'BLOCK');
  const amount = result.entities.find((e) => e.category === 'FINANCIAL_RECORD');
  assert.equal(amount?.decision, 'ALLOW');
});

test('5. Policy engine enforces core principle: task relevance does not override destination permission', () => {
  const maScenario = WORKFLOW_SCENARIOS[3];
  const result = evaluateWorkflowContext(maScenario.rawPrompt, maScenario.taskObjective, 'mcp-plugin');
  assert.equal(result.principleTriggered, true);
  assert.ok(!result.sanitizedPrompt.includes('Project Helios'));
  assert.ok(!result.sanitizedPrompt.includes('$48.2M'));
});

test('6. Engine overrides can only tighten decisions, never weaken them', () => {
  const prompt = 'Evaluate Project Helios ($48.2M) and key sk_live_98a7f65c44b2109d';
  const result = evaluateWorkflowContext(prompt, 'rotate key and summarize valuation memo', 'mcp-plugin', {
    'entity-1': 'ALLOW',
    'entity-2': 'ALLOW',
    'entity-3': 'ALLOW',
  });
  assert.deepEqual(result.entities.map((e) => e.decision), ['BLOCK', 'REDACT', 'REDACT']);
});
