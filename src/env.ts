/**
 * Skeleton stage: no service-specific env vars yet. Real vars land here
 * when business logic is ported from services/aws-accounts-api/.
 * Cloud Run reads these as plain container environment variables (set via
 * `gcloud run deploy --set-env-vars` / `--set-secrets`), not Wrangler
 * bindings.
 */
export interface Env {
  SERVICE_ENV: string;
}
