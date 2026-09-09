import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Acceptance condition 1: "No browser calls /discovery/run-step,
 * /discovery/finalize, CUR ingest-step/finalize, or equivalent worker-only
 * endpoints."
 *
 * Phase 1 removed the browser's calls and Phase 3 replaced the loop with
 * durable collection runs — but the ROUTES stayed mounted for both phases,
 * and were reported as removed on the strength of a GET probe returning 404
 * against POST-only routes. Checking the shipped bundle proved the browser
 * had stopped calling them; nobody checked whether the server had stopped
 * offering them.
 *
 * They were not merely redundant. A hand-crafted authenticated request could
 * drive a scan step with no lease, no checkpoint and no run row — outside
 * the durable machinery entirely. The partial unique index that makes "one
 * job despite repeated clicks" true guards `collection_runs`, and a caller
 * who never creates one is not covered by it.
 *
 * These assertions are on the SERVER source, deliberately: the equivalent
 * frontend test asserts the browser does not call them, which is a
 * different and weaker claim.
 */
function source(file: string): string {
  return readFileSync(join(__dirname, file), 'utf8');
}

function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('the browser-era worker endpoints are not mounted', () => {
  const discovery = code(source('discovery.ts'));
  const cur = code(source('cur.ts'));

  it('does not register discovery/run-step', () => {
    expect(discovery).not.toMatch(/discoveryRoutes\.post\(\s*'\/accounts\/:id\/discovery\/run-step'/);
  });

  it('does not register discovery/finalize', () => {
    expect(discovery).not.toMatch(/discoveryRoutes\.post\(\s*'\/accounts\/:id\/discovery\/finalize'/);
  });

  it('does not register cur/ingest-step', () => {
    expect(cur).not.toMatch(/curRoutes\.post\(\s*'\/accounts\/:id\/cur\/ingest-step'/);
  });
});

describe('the durable worker keeps the step functions it actually uses', () => {
  const discovery = source('discovery.ts');
  const collectionRuns = code(source('collectionRuns.ts'));

  /**
   * The distinction that made removal safe: collectionRuns.ts imports these
   * FUNCTIONS directly. Only the HTTP surface was dead. A future edit that
   * deletes the functions along with the routes would silently break the
   * durable runs, so both halves are pinned here.
   */
  for (const fn of ['runResourceStep', 'runFindingStep', 'runMetricStep', 'runFinalize']) {
    it(`still exports ${fn}`, () => {
      expect(discovery).toMatch(new RegExp(`export async function ${fn}\\b`));
    });
  }

  it('drives steps through the imported functions, not over HTTP', () => {
    expect(collectionRuns).toMatch(/from '\.\/discovery'/);
    expect(collectionRuns).toMatch(/runFinalize\(/);
    // An internal fetch back into our own HTTP surface would reintroduce the
    // unleased path through the back door.
    expect(collectionRuns).not.toMatch(/discovery\/run-step|discovery\/finalize/);
  });
});
