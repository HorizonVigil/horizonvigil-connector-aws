import { callQueryApi, extractXmlField, type AwsCreds } from './awsApi';

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

  // Use the common signed-call path rather than raw AwsClient.fetch so this
  // security-sensitive call has the same abort deadline, retry policy and
  // response normalization as every other AWS request in the connector.
  const result = await callQueryApi(
    { accessKeyId: platformCreds.accessKeyId, secretAccessKey: platformCreds.secretAccessKey },
    {
      service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com',
      action: 'AssumeRole', version: '2011-06-15',
      params: { RoleArn: roleArn, RoleSessionName: 'horizonvigil-validation', ExternalId: externalId, DurationSeconds: '900' },
    },
  );
  const text = typeof result.body === 'string' ? result.body : '';
  if (!result.ok) {
    return { ok: false, reason: extractXmlField(text, 'Message') ?? result.errorMessage ?? `AssumeRole failed (${extractXmlField(text, 'Code') ?? result.errorCode ?? result.status})` };
  }
  const accessKeyId = extractXmlField(text, 'AccessKeyId');
  const secretAccessKey = extractXmlField(text, 'SecretAccessKey');
  const sessionToken = extractXmlField(text, 'SessionToken');
  if (!accessKeyId || !secretAccessKey || !sessionToken) {
    return { ok: false, reason: 'AssumeRole succeeded but the response was missing expected credential fields.' };
  }
  return { ok: true, credentials: { accessKeyId, secretAccessKey, sessionToken } };
}
