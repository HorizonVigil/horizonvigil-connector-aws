import { AwsClient } from 'aws4fetch';
import { extractXmlField } from './awsApi';
import type { AwsCreds } from './awsApi';

export interface AssumeRoleOutcome {
  ok: boolean;
  credentials?: AwsCreds;
  reason?: string;
}

/**
 * STS AssumeRole for cross-account-role connections — needs the platform's
 * OWN AWS credentials (PLATFORM_AWS_ACCESS_KEY_ID/SECRET) to call
 * sts:AssumeRole against the customer's trust policy; those aren't
 * provisioned in this environment yet. Returns an honest `ok: false` with a
 * clear reason rather than silently skipping or faking a result — the
 * caller (routes/permissions.ts) surfaces `reason` directly to the user.
 */
export async function assumeConnectionRole(
  platformCreds: { accessKeyId?: string; secretAccessKey?: string },
  roleArn: string,
  externalId: string,
): Promise<AssumeRoleOutcome> {
  if (!platformCreds.accessKeyId || !platformCreds.secretAccessKey) {
    return { ok: false, reason: 'Platform AWS credentials (PLATFORM_AWS_ACCESS_KEY_ID/SECRET) are not configured on this Worker — cross-account-role validation is not available until they are.' };
  }

  const client = new AwsClient({ accessKeyId: platformCreds.accessKeyId, secretAccessKey: platformCreds.secretAccessKey, service: 'sts', region: 'us-east-1' });
  const body = new URLSearchParams({
    Action: 'AssumeRole',
    Version: '2011-06-15',
    RoleArn: roleArn,
    RoleSessionName: 'cloudops360-validation',
    ExternalId: externalId,
    DurationSeconds: '900',
  }).toString();

  try {
    const res = await client.fetch('https://sts.amazonaws.com/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const text = await res.text();
    if (!res.ok) {
      return { ok: false, reason: extractXmlField(text, 'Message') ?? `AssumeRole failed (${extractXmlField(text, 'Code') ?? res.status})` };
    }
    const accessKeyId = extractXmlField(text, 'AccessKeyId');
    const secretAccessKey = extractXmlField(text, 'SecretAccessKey');
    const sessionToken = extractXmlField(text, 'SessionToken');
    if (!accessKeyId || !secretAccessKey || !sessionToken) {
      return { ok: false, reason: 'AssumeRole succeeded but the response was missing expected credential fields.' };
    }
    return { ok: true, credentials: { accessKeyId, secretAccessKey, sessionToken } };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'AssumeRole request failed' };
  }
}
