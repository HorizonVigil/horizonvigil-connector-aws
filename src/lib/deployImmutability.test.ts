import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

/**
 * AWS-C2. Production must never deploy a mutable image tag.
 *
 * THE INCIDENT. During the 2026-09-22 production review, Cloud Run revision
 * 00213 was found serving digest 215eddfb… while the deploy of record (00211)
 * was 60ff89f2…. A build nobody in that session ran had replaced `:latest` at
 * 13:35 UTC, silently reverting verified fixes: `degraded_reasons` read 0
 * until a redeploy, then immediately populated. A fix can be verified in
 * production and be gone an hour later with no signal.
 *
 * These assertions are the control. Comments explaining why `:latest` is
 * dangerous do not stop anyone from deploying it; a failing test does.
 */
const CLOUDBUILD = readFileSync('cloudbuild.yaml', 'utf8');
const WORKFLOW = readFileSync('.github/workflows/deploy.yml', 'utf8');

/** Comment lines stripped, so prose about `:latest` cannot satisfy — or trip — a check on code. */
const code = (src: string, commentPrefixes: RegExp) =>
  src.split('\n').filter((l) => !commentPrefixes.test(l)).join('\n');

const CLOUDBUILD_CODE = code(CLOUDBUILD, /^\s*#/);
const WORKFLOW_CODE = code(WORKFLOW, /^\s*#/);

describe('cloudbuild.yaml never deploys a mutable tag', () => {
  it('deploys an interpolated tag, never a literal :latest', () => {
    expect(CLOUDBUILD_CODE).toContain('--image="$$IMAGE:$$TAG"');
    expect(CLOUDBUILD_CODE).not.toMatch(/--image=[^\n]*:latest/);
  });

  it('refuses the literal tag "latest" before building', () => {
    expect(CLOUDBUILD_CODE).toMatch(/latest\|Latest\|LATEST/);
    expect(CLOUDBUILD_CODE).toMatch(/REFUSING/);
  });

  /**
   * The structural guard, and the one that matters most: it does not
   * blacklist a known-bad string, it whitelists a known-good SHAPE. An empty
   * tag, a half-substituted variable and a tag nobody anticipated all fail.
   */
  it('accepts only a 40-hex commit SHA or an explicit build-<id> fallback', () => {
    expect(CLOUDBUILD_CODE).toMatch(/\^\(\[0-9a-f\]\{40\}\|build-\[A-Za-z0-9_-\]\+\)\$/);
  });

  it('re-checks the tag at the point of deploy, not only at build time', () => {
    // The tag travels through a file between build steps. A check that ran
    // three steps ago does not protect the line that actually deploys.
    const deployStep = CLOUDBUILD_CODE.slice(CLOUDBUILD_CODE.indexOf('id: deploy'));
    expect(deployStep).toMatch(/latest\|Latest\|LATEST/);
  });

  it('captures the pushed digest', () => {
    expect(CLOUDBUILD_CODE).toContain('/workspace/image_digest');
    expect(CLOUDBUILD_CODE).toMatch(/RepoDigests/);
  });

  it('verifies the SERVING revision after deploying, not just the API call', () => {
    expect(CLOUDBUILD_CODE).toContain('latestReadyRevisionName');
    expect(CLOUDBUILD_CODE).toMatch(/SERVING_IMAGE.*!=.*IMAGE:\$\$TAG|"\$\$SERVING_IMAGE" != "\$\$IMAGE:\$\$TAG"/);
  });

  it('fails the build if the tag moved between push and deploy', () => {
    expect(CLOUDBUILD_CODE).toContain('Another build moved the tag');
  });

  /**
   * `gcloud run deploy --image` without --set-env-vars PRESERVES the existing
   * environment. Passing --set-env-vars here would REPLACE the whole set and
   * drop every secret the service holds.
   */
  it('does not rewrite the environment on an image-only deploy', () => {
    const deployStep = CLOUDBUILD_CODE.slice(CLOUDBUILD_CODE.indexOf('id: deploy'));
    expect(deployStep).not.toContain('--set-env-vars');
  });
});

describe('deploy.yml never deploys a mutable tag', () => {
  it('builds from the commit SHA', () => {
    expect(WORKFLOW_CODE).toContain('TAG="${{ github.sha }}"');
  });

  it('refuses anything that is not a 40-hex commit SHA', () => {
    expect(WORKFLOW_CODE).toMatch(/\^\[0-9a-f\]\{40\}\$/);
    expect(WORKFLOW_CODE).toMatch(/REFUSING/);
  });

  it('never references a :latest tag in an image or deploy line', () => {
    expect(WORKFLOW_CODE).not.toMatch(/--image=[^\n]*:latest/);
    expect(WORKFLOW_CODE).not.toMatch(/IMAGE="[^"]*:latest"/);
  });

  it('captures the pushed digest', () => {
    expect(WORKFLOW_CODE).toContain('IMAGE_DIGEST=');
    expect(WORKFLOW_CODE).toMatch(/RepoDigests/);
  });

  it('verifies the serving revision and refuses a mutable one', () => {
    expect(WORKFLOW_CODE).toContain('latestReadyRevisionName');
    expect(WORKFLOW_CODE).toContain('production is serving a mutable tag');
  });

  it('fails the deploy if the tag moved between push and deploy', () => {
    expect(WORKFLOW_CODE).toContain('Another build moved the tag');
  });
});

/**
 * Requirement 8. This workflow sets the environment with `--set-env-vars`,
 * which REPLACES the whole set rather than merging — so a variable missing
 * from that payload is silently deleted on the next deploy.
 *
 * Measured 2026-09-22: `ALERTS_API_URL` was set on the live service to wire
 * the C1 alert-evaluation hook, and was absent from this payload. The next
 * Actions deploy would have wiped it and returned the hook to its "not
 * configured" 503 — failing silently, exactly the way the original C1 defect
 * did.
 */
describe('the workflow preserves every variable the service needs', () => {
  const payload = /--set-env-vars="\^##\^(.*?)"/s.exec(WORKFLOW)?.[1] ?? '';
  const names = new Set(payload.split('##').filter((p) => p.includes('=')).map((p) => p.split('=')[0]));

  /** Every variable connector-aws reads. Sourced from the live service, 2026-09-22. */
  const REQUIRED = [
    'SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY',
    'ALLOWED_ORIGIN', 'DB_SCHEMA', 'ENCRYPTION_KEY',
    'INTERNAL_SCAN_SECRET', 'INTERNAL_COST_SYNC_SECRET', 'POST_SCAN_HOOK_SECRET',
    'AUTOMATION_API_URL', 'COST_OPTIMIZATION_API_URL', 'ALERTS_API_URL',
  ];

  it('sets a non-empty environment payload', () => {
    expect(names.size).toBeGreaterThan(0);
  });

  it.each(REQUIRED)('still sets %s', (name) => {
    expect(names.has(name), `${name} would be WIPED by the next deploy`).toBe(true);
  });

  it('ALERTS_API_URL specifically — the one that was missing', () => {
    // Without it the C1 alert hook reverts to 503 on the next deploy, and
    // nothing would say so until someone went looking for an alert that
    // never arrived.
    expect(names.has('ALERTS_API_URL')).toBe(true);
    expect(payload).toContain('ALERTS_API_URL=https://observability-');
  });
});
