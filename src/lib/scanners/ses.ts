import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SES_RESOURCE_TYPES = ['ses_configuration_set', 'ses_identity'] as const;

interface ListConfigurationSetsResponse { ConfigurationSets?: string[]; NextToken?: string }
interface EmailIdentity { IdentityName?: string; IdentityType?: string; SendingEnabled?: boolean; VerificationStatus?: string }
interface ListEmailIdentitiesResponse { EmailIdentities?: EmailIdentity[]; NextToken?: string }

/**
 * Amazon SES v2 (SESv2) configuration sets + email/domain identities.
 * REST-JSON, GET requests (list operations only, no request body).
 *
 * Hostname quirk, confirmed against botocore's own sesv2 service-2.json
 * metadata (endpointPrefix "email", signingName "ses") rather than assumed
 * from convention: SESv2's real REST endpoint host is
 * `email.<region>.amazonaws.com`, NOT `ses.<region>.amazonaws.com` the way
 * most other services' hostname prefix matches their own IAM action prefix.
 * The SigV4 *signing* name is still `ses` though (that's what IAM policies
 * and the request's credential scope use) -- so createAwsClient below is
 * constructed with service='ses' while the request URL uses the 'email.'
 * host. Mixing these two up either breaks the signature (wrong signing
 * name) or 404s (wrong host), so both are called out explicitly here for
 * whoever debugs this against a live account next.
 *
 * Regional, not global -- SES/SESv2 is only available in a subset of AWS
 * regions; scanning a region without it just fails cleanly like any other
 * optional-service scanner here, logged and skipped rather than thrown.
 * The two list calls (configuration sets, identities) are independently
 * fail-soft -- one failing doesn't stop the other from being attempted.
 *
 * UNVERIFIED against a real account's actual response shape until this runs
 * against a live connection and gets checked -- same disclosed-uncertainty
 * convention as inspector2.ts/inspectorFindings.ts. Per AWS's published
 * ListConfigurationSets/ListEmailIdentities API reference: the former
 * returns plain configuration-set name strings (no separate ARN/ID field),
 * paginated via NextToken/PageSize query params; the latter returns
 * IdentityName/IdentityType/SendingEnabled/VerificationStatus per identity,
 * same pagination shape. Neither has been exercised against a live
 * SES-enabled account from this connector yet.
 */
export async function scanSes(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'ses', ctx.region);
  const base = `https://email.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`SES GET ${path} failed in ${ctx.region} (continuing without it — likely just not available/enabled there): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  // Configuration sets -- independently fail-soft from identities below.
  {
    let nextToken: string | undefined;
    do {
      const qs = new URLSearchParams({ PageSize: '100', ...(nextToken ? { NextToken: nextToken } : {}) });
      const body = (await getJson(`/v2/email/configuration-sets?${qs.toString()}`)) as ListConfigurationSetsResponse | null;
      if (!body) break;
      for (const name of body.ConfigurationSets ?? []) {
        out.push({
          resourceTypeKey: 'ses_configuration_set', resourceId: name, region: ctx.region, resourceName: name,
        });
      }
      nextToken = body.NextToken;
    } while (nextToken);
  }

  // Email/domain identities -- independently fail-soft from configuration sets above.
  {
    let nextToken: string | undefined;
    do {
      const qs = new URLSearchParams({ PageSize: '100', ...(nextToken ? { NextToken: nextToken } : {}) });
      const body = (await getJson(`/v2/email/identities?${qs.toString()}`)) as ListEmailIdentitiesResponse | null;
      if (!body) break;
      for (const identity of body.EmailIdentities ?? []) {
        if (!identity.IdentityName) continue;
        out.push({
          resourceTypeKey: 'ses_identity', resourceId: identity.IdentityName, region: ctx.region, resourceName: identity.IdentityName,
          state: identity.VerificationStatus,
          metadata: { identityType: identity.IdentityType ?? null, sendingEnabled: identity.SendingEnabled ?? null },
        });
      }
      nextToken = body.NextToken;
    } while (nextToken);
  }

  return out;
}
