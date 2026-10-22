import { PolicyDecision } from './types.ts';
import { evaluateWorkflowContext } from './engine.ts';
import { SYNTHETIC_EVALUATION_CASES } from './evaluationCases.ts';

export { SYNTHETIC_EVALUATION_CASES };

export function runEvaluationBenchmark() {
  let aCaseMatches = 0;
  let bCaseMatches = 0;
  let cCaseMatches = 0;

  let aActionMatches = 0;
  let bActionMatches = 0;
  let cActionMatches = 0;

  let aDisclosures = 0;
  let bDisclosures = 0;
  let cDisclosures = 0;

  let aMissed = 0;
  let bMissed = 0;
  let cMissed = 0;

  let aOverRedactions = 0;
  let bOverRedactions = 0;
  let cOverRedactions = 0;

  let aViolations = 0;
  let bViolations = 0;
  let cViolations = 0;

  let aTP = 0, aFP = 0, aFN = 0;
  let bTP = 0, bFP = 0, bFN = 0;
  let cTP = 0, cFP = 0, cFN = 0;

  const caseResults = SYNTHETIC_EVALUATION_CASES.map((tc) => {
    const cg = evaluateWorkflowContext(tc.rawPrompt, tc.taskObjective, tc.destinationId);

    // 1. Evaluate System C (ContextGuard)
    let cEntitiesOk = true;
    let cCaseDisclosures = 0;
    let cCaseMissed = 0;
    let cCaseOverRedactions = 0;
    let cCaseViolations = 0;

    for (const exp of tc.expectedEntities) {
      const actual = cg.entities.find((e) => e.value === exp.value)?.decision;
      if (!actual) {
        cEntitiesOk = false;
        cMissed++;
        cCaseMissed++;
        if (exp.expectedDecision !== 'ALLOW') {
          cDisclosures++;
          cViolations++;
          cFN++;
          cCaseDisclosures++;
          cCaseViolations++;
        }
        continue;
      }
      if (actual !== exp.expectedDecision) cEntitiesOk = false;
      if (exp.expectedDecision === 'ALLOW') {
        if (actual !== 'ALLOW') {
          cOverRedactions++;
          cFP++;
          cCaseOverRedactions++;
        }
      } else {
        if (actual === 'ALLOW') {
          cDisclosures++;
          cViolations++;
          cFN++;
          cCaseDisclosures++;
          cCaseViolations++;
        } else if (exp.expectedDecision === 'BLOCK' && actual !== 'BLOCK') {
          cViolations++;
          cFN++;
          cCaseViolations++;
        } else {
          cTP++;
        }
      }
    }
    const cActionMatched = cg.overallAction === tc.expectedAction;
    if (cActionMatched) cActionMatches++;
    const cPassed = cActionMatched && cEntitiesOk;
    if (cPassed) cCaseMatches++;

    // 2. Evaluate Baseline A (Keyword-Only Static DLP)
    let aEntitiesOk = true;
    let aBlocked = 0;
    let aRedacted = 0;
    let aCaseDisclosures = 0;
    let aCaseMissed = 0;
    let aCaseOverRedactions = 0;
    let aCaseViolations = 0;

    for (const ent of cg.entities) {
      if (ent.category === 'PROPRIETARY_CODENAME') continue;
      if (
        ent.category === 'API_CREDENTIAL' ||
        ent.category === 'INFRASTRUCTURE_URI' ||
        ent.category === 'NATIONAL_ID'
      ) {
        aBlocked++;
      } else {
        aRedacted++;
      }
    }
    const aAction =
      aBlocked > 0 ? 'HALT_OUTBOUND' : aRedacted > 0 ? 'TRANSMIT_SANITIZED' : 'TRANSMIT_AS_IS';

    for (const exp of tc.expectedEntities) {
      const aDecision: PolicyDecision | undefined =
        exp.category === 'PROPRIETARY_CODENAME'
          ? undefined
          : exp.category === 'API_CREDENTIAL' ||
            exp.category === 'INFRASTRUCTURE_URI' ||
            exp.category === 'NATIONAL_ID'
          ? 'BLOCK'
          : 'REDACT';

      if (!aDecision) {
        aEntitiesOk = false;
        aMissed++;
        aCaseMissed++;
        if (exp.expectedDecision !== 'ALLOW') {
          aDisclosures++;
          aViolations++;
          aFN++;
          aCaseDisclosures++;
          aCaseViolations++;
        }
        continue;
      }
      if (aDecision !== exp.expectedDecision) aEntitiesOk = false;
      if (exp.expectedDecision === 'ALLOW') {
        // Baseline A never allows a detected entity, so every expected-ALLOW entity is an unnecessary redaction.
        aOverRedactions++;
        aFP++;
        aCaseOverRedactions++;
      } else {
        aTP++;
      }
    }
    const aActionMatched = aAction === tc.expectedAction;
    if (aActionMatched) aActionMatches++;
    const aPassed = aActionMatched && aEntitiesOk;
    if (aPassed) aCaseMatches++;

    // 3. Evaluate Baseline B (Relevance Without Destination Auth)
    let bEntitiesOk = true;
    let bBlocked = 0;
    let bRedacted = 0;
    let bCaseDisclosures = 0;
    let bCaseMissed = 0;
    let bCaseOverRedactions = 0;
    let bCaseViolations = 0;

    for (const ent of cg.entities) {
      if (ent.relevanceLevel === 'REQUIRED') continue;
      if (
        ent.category === 'API_CREDENTIAL' ||
        ent.category === 'INFRASTRUCTURE_URI' ||
        ent.category === 'NATIONAL_ID'
      ) {
        bBlocked++;
      } else {
        bRedacted++;
      }
    }
    const bAction =
      bBlocked > 0 ? 'HALT_OUTBOUND' : bRedacted > 0 ? 'TRANSMIT_SANITIZED' : 'TRANSMIT_AS_IS';

    for (const exp of tc.expectedEntities) {
      const detected = cg.entities.find((e) => e.value === exp.value);
      const bDecision: PolicyDecision | undefined = !detected
        ? undefined
        : detected.relevanceLevel === 'REQUIRED'
        ? 'ALLOW'
        : detected.category === 'API_CREDENTIAL' ||
          detected.category === 'INFRASTRUCTURE_URI' ||
          detected.category === 'NATIONAL_ID'
        ? 'BLOCK'
        : 'REDACT';

      if (!bDecision) {
        bEntitiesOk = false;
        bMissed++;
        bCaseMissed++;
        if (exp.expectedDecision !== 'ALLOW') {
          bDisclosures++;
          bViolations++;
          bFN++;
          bCaseDisclosures++;
          bCaseViolations++;
        }
        continue;
      }
      if (bDecision !== exp.expectedDecision) bEntitiesOk = false;
      if (exp.expectedDecision === 'ALLOW') {
        if (bDecision !== 'ALLOW') {
          bOverRedactions++;
          bFP++;
          bCaseOverRedactions++;
        }
      } else {
        if (bDecision === 'ALLOW') {
          bDisclosures++;
          bViolations++;
          bFN++;
          bCaseDisclosures++;
          bCaseViolations++;
        } else if (exp.expectedDecision === 'BLOCK' && bDecision !== 'BLOCK') {
          bViolations++;
          bFN++;
          bCaseViolations++;
        } else {
          bTP++;
        }
      }
    }
    const bActionMatched = bAction === tc.expectedAction;
    if (bActionMatched) bActionMatches++;
    const bPassed = bActionMatched && bEntitiesOk;
    if (bPassed) bCaseMatches++;

    return {
      caseId: tc.id,
      category: tc.category,
      destinationId: tc.destinationId,
      expectedAction: tc.expectedAction,
      outcomes: {
        keyword_only: {
          passed: aPassed,
          actionMatched: aActionMatched,
          action: aAction,
          unauthorizedDisclosures: aCaseDisclosures,
          missedDetections: aCaseMissed,
          unnecessaryRedactions: aCaseOverRedactions,
          policyViolations: aCaseViolations,
        },
        relevance_without_auth: {
          passed: bPassed,
          actionMatched: bActionMatched,
          action: bAction,
          unauthorizedDisclosures: bCaseDisclosures,
          missedDetections: bCaseMissed,
          unnecessaryRedactions: bCaseOverRedactions,
          policyViolations: bCaseViolations,
        },
        context_guard: {
          passed: cPassed,
          actionMatched: cActionMatched,
          action: cg.overallAction,
          unauthorizedDisclosures: cCaseDisclosures,
          missedDetections: cCaseMissed,
          unnecessaryRedactions: cCaseOverRedactions,
          policyViolations: cCaseViolations,
        },
      },
    };
  });

  const total = SYNTHETIC_EVALUATION_CASES.length;
  const calcScores = (
    caseMatches: number,
    actionMatches: number,
    disclosures: number,
    missed: number,
    overRedactions: number,
    violations: number,
    tp: number,
    fp: number,
    fn: number
  ) => {
    const p = tp + fp > 0 ? tp / (tp + fp) : 0;
    const r = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = p + r > 0 ? (2 * p * r) / (p + r) : 0;
    return {
      exactCaseMatches: caseMatches,
      exactActionMatches: actionMatches,
      accuracyPct: total > 0 ? Math.round((caseMatches / total) * 10000) / 100 : 0,
      actionAccuracyPct: total > 0 ? Math.round((actionMatches / total) * 10000) / 100 : 0,
      unauthorizedDisclosureCount: disclosures,
      missedDetectionCount: missed,
      unnecessaryRedactionCount: overRedactions,
      policyViolationCount: violations,
      precision: Math.round(p * 100) / 100,
      recall: Math.round(r * 100) / 100,
      f1Score: Math.round(f1 * 100) / 100,
    };
  };

  return {
    evaluatedAt: new Date().toISOString(),
    benchmarkScope: 'SYNTHETIC_PROTOTYPE_BENCHMARK',
    validationDisclaimer:
      `Metrics are calculated dynamically from ${total} labelled synthetic test cases and represent prototype validation rather than production traffic.`,
    totalTestCases: total,
    comparison: {
      keyword_only: {
        name: 'A. Keyword-Only Static DLP',
        ...calcScores(aCaseMatches, aActionMatches, aDisclosures, aMissed, aOverRedactions, aViolations, aTP, aFP, aFN),
      },
      relevance_without_auth: {
        name: 'B. Relevance Without Destination Auth',
        ...calcScores(bCaseMatches, bActionMatches, bDisclosures, bMissed, bOverRedactions, bViolations, bTP, bFP, bFN),
      },
      context_guard: {
        name: 'C. ContextGuard (Relevance + Destination Policy)',
        ...calcScores(cCaseMatches, cActionMatches, cDisclosures, cMissed, cOverRedactions, cViolations, cTP, cFP, cFN),
      },
    },
    caseResults,
  };
}
