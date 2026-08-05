import type { Env as BaseEnv } from '@cloudops360/shared-lib';

/**
 * Cloud Run reads these as plain container environment variables (set via
 * `gcloud run deploy --set-env-vars` / `--set-secrets`), not Wrangler
 * bindings — this repo targets Cloud Run only.
 */
export interface Env extends BaseEnv {
  ENCRYPTION_KEY: string;
  // Only needed to validate cross-account-role connections (sts:AssumeRole
  // against the customer's trust policy) — access-key connections validate
  // using their own stored credentials and don't need these. Not currently
  // provisioned in this environment; assumeRole.ts degrades to an honest
  // "not configured" result when absent, see routes/permissions.ts.
  PLATFORM_AWS_ACCESS_KEY_ID?: string;
  PLATFORM_AWS_SECRET_ACCESS_KEY?: string;
  // Public URL for automation-api's event dispatcher (Slack/Jira fan-out on
  // remediation completion) — not sensitive, same convention as every other
  // cross-service URL in this app.
  AUTOMATION_API_URL?: string;
}
