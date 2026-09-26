import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';

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
const WORKFLOW_PATH = '.github/workflows/deploy.yml';
const HAS_WORKFLOW = existsSync(WORKFLOW_PATH);
const WORKFLOW = HAS_WORKFLOW ? readFileSync(WORKFLOW_PATH, 'utf8') : '';

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
  /**
   * Production deploys from cloudbuild.yaml ONLY. `main` removed the
   * production deploy job from GitHub Actions (the same "stop deploying from
   * GitHub Actions" change already applied to admin, cost, resources and
   * llm), so this workflow builds, tests, and deploys the separate TEST
   * project — nothing else.
   *
   * That is asserted rather than assumed: if a production deploy job is ever
   * added back here, it reintroduces a second production path that the
   * cloudbuild guards do not cover, and this fails.
   */
  it('has no production deploy job — cloudbuild.yaml is the only prod path', () => {
    if (!HAS_WORKFLOW) {
      expect(WORKFLOW).toBe('');
      return;
    }
    // Scoped to the jobs block — `on:` has two-space keys too (`push:`).
    const jobsBlock = WORKFLOW.slice(WORKFLOW.indexOf('\njobs:'));
    const jobs = [...jobsBlock.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]);
    expect(jobs).toEqual(['build-and-test', 'deploy-test']);
    expect(jobs).not.toContain('deploy');
  });

  it('the one deploy it does perform is guarded too', () => {
    if (!HAS_WORKFLOW) {
      expect(WORKFLOW).toBe('');
      return;
    }
    expect(WORKFLOW_CODE).toContain('TAG="${{ github.sha }}"');
    expect(WORKFLOW_CODE).toMatch(/\^\[0-9a-f\]\{40\}\$/);
    expect(WORKFLOW_CODE).toMatch(/REFUSING/);
  });

  it('never references a :latest tag in an image or deploy line', () => {
    expect(WORKFLOW_CODE).not.toMatch(/--image=\S*:latest/);
    expect(WORKFLOW_CODE).not.toMatch(/IMAGE="[^"]*:latest"/);
  });

  it('every action is pinned to a commit SHA (AWS-L1)', () => {
    if (!HAS_WORKFLOW) {
      expect(WORKFLOW).toBe('');
      return;
    }
    // Re-applied after the merge: origin/main branched before L1 and its
    // version had reverted to mutable tags.
    const uses = [...WORKFLOW.matchAll(/uses: (\S+)/g)].map((m) => m[1]);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u, u).toMatch(/@[0-9a-f]{40}$/);
  });
});

/**
 * Requirement 8, after the merge.
 *
 * The production deploy job that carried `--set-env-vars` is gone from this
 * workflow, and cloudbuild.yaml deliberately passes NO `--set-env-vars` — so
 * `gcloud run deploy --image` preserves the service's existing environment
 * instead of replacing it. That is what keeps all twelve variables, including
 * ALERTS_API_URL, alive across a deploy.
 *
 * Verified live on revision connector-aws-00226-5h9: 12/12 present and the C1
 * hook still answering.
 */
describe('a deploy preserves the environment rather than replacing it', () => {
  it('cloudbuild does not rewrite the environment', () => {
    expect(CLOUDBUILD_CODE).not.toContain('--set-env-vars');
  });

  it('the remaining workflow env payload targets the TEST project, not production', () => {
    const payload = /--set-env-vars="([^"]*)"/.exec(WORKFLOW)?.[1] ?? '';
    if (payload) {
      // The production Supabase project must never be written by the
      // test-environment deploy.
      expect(payload).not.toContain('dvyoghaqeknyyrdujssi');
    }
  });
});
