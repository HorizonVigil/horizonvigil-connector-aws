/**
 * Redaction for text that came from AWS and is about to be shown to a person.
 *
 * WHY THIS EXISTS
 *
 * Every permission probe ends with some variant of
 *
 *     detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}`
 *
 * which passes AWS's own error text straight through to
 * `connection_permission_checks.detail` — a column rendered on the account
 * page, returned by the API, and written to logs. AWS error messages routinely
 * quote the principal that was refused, and for an IAM-user principal that
 * text contains the access-key ID.
 *
 * Rule 12 forbids exposing access-key identifiers in UI, logs, events, reports
 * or telemetry. A permission-check detail is four of those five at once.
 *
 * The CloudTrail change feed already redacts exactly this
 * (`routes/cloudtrailEvents.ts`); the probes never did. Found by a test that
 * asserted no probe echoes credential material and watched Inspector return
 * `failed for AKIA_TEST` verbatim.
 *
 * REDACTED, NOT BLANKED
 *
 * The surrounding message is the actionable part — "User: … is not authorized
 * to perform: guardduty:ListDetectors" tells someone exactly which permission
 * to add. Dropping the whole string to be safe would remove the only thing
 * that makes the check useful.
 */

/** Long-lived (AKIA) and temporary (ASIA) AWS access-key identifiers. */
const ACCESS_KEY_ID = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;

/**
 * Session tokens and secret access keys never appear in AWS error text, so
 * they are not matched here — a pattern broad enough to catch an arbitrary
 * base64 secret would redact half of every legitimate ARN and message.
 */
export function redactAwsText(value: string): string;
export function redactAwsText(value: string | null): string | null;
export function redactAwsText(value: string | null): string | null {
  if (value === null) return null;
  return value.replace(ACCESS_KEY_ID, '[redacted access key]');
}
