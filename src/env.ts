import type { Env as BaseEnv } from '@horizonvigil/shared-lib';

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
  // The AWS account ID those credentials belong to -- the AWS Organizations
  // bulk-import StackSet template (templates/horizonvigil-scan-role-
  // stackset.yaml) needs this as its trust policy's Principal, not the
  // credentials themselves. Same "not currently provisioned, degrade
  // honestly" status as the two above -- see routes/bulkImport.ts.
  PLATFORM_AWS_ACCOUNT_ID?: string;
  // Public URL for automation-api's event dispatcher (Slack/Jira fan-out on
  // remediation completion) — not sensitive, same convention as every other
  // cross-service URL in this app.
  AUTOMATION_API_URL?: string;
  // Shared secret a Cloud Scheduler job presents (X-Internal-Scan-Secret
  // header) to call POST /internal/run-due-scans — see routes/internalScan.ts.
  // Not currently provisioned in any environment; that route returns an
  // honest 503 rather than running with no auth check when this is unset.
  INTERNAL_SCAN_SECRET?: string;
  // Public Cloud Run URL for cost-optimization-api's POST
  // /internal/generate-recommendations, called (best-effort) from
  // runFinalize after every discovery run — see lib/postScanHooks.ts. Not
  // sensitive, same convention as AUTOMATION_API_URL above.
  COST_OPTIMIZATION_API_URL?: string;
  // Public Cloud Run URL for observability-api's POST
  // /internal/evaluate-alert-rules, called (best-effort) from runFinalize
  // the same way — see lib/postScanHooks.ts.
  ALERTS_API_URL?: string;
  // A separate shared secret from INTERNAL_SCAN_SECRET above, presented as
  // X-Internal-Scan-Secret when runFinalize calls out to cost-optimization-
  // api/observability-api's own /internal/* routes. Deliberately its own
  // value rather than reusing INTERNAL_SCAN_SECRET: that one already
  // authenticates real, live Cloud Scheduler jobs calling INTO this
  // service, and rotating it to also serve this new outbound direction
  // would risk breaking those without also updating the scheduler jobs in
  // lockstep. Same value must be set as POST_SCAN_HOOK_SECRET on
  // cost-optimization-api and observability-api.
  POST_SCAN_HOOK_SECRET?: string;
}
