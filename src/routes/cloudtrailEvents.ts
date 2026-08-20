import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { callJsonApi } from '../lib/awsApi';
import { resolveCredentials, type ResolvableConnection } from './permissions';

export const cloudtrailEventsRoutes = new Hono<{ Bindings: Env }>();

const LOOKUP_ATTRIBUTE_KEYS = new Set(['Username', 'EventName', 'ResourceName', 'ResourceType', 'EventSource', 'AccessKeyId', 'ReadOnly']);

interface RawCloudTrailEvent {
  EventId: string; EventName: string; EventTime: number; EventSource: string; Username?: string;
  Resources?: { ResourceType?: string; ResourceName?: string }[];
  CloudTrailEvent: string;
}

interface ParsedDetail {
  eventVersion?: string;
  userIdentity?: { type?: string; arn?: string; accountId?: string; userName?: string; invokedBy?: string; sessionContext?: { sessionIssuer?: { type?: string; arn?: string } } };
  sourceIPAddress?: string; userAgent?: string; awsRegion?: string; readOnly?: boolean;
  errorCode?: string; errorMessage?: string;
  requestParameters?: unknown; responseElements?: unknown; managementEvent?: boolean; eventType?: string;
}

function mapEvent(e: RawCloudTrailEvent) {
  let detail: ParsedDetail = {};
  try { detail = JSON.parse(e.CloudTrailEvent) as ParsedDetail; } catch { /* leave detail empty if AWS ever returns a malformed string */ }
  return {
    eventId: e.EventId,
    eventName: e.EventName,
    eventTime: new Date(e.EventTime * 1000).toISOString(),
    eventSource: e.EventSource,
    username: e.Username ?? detail.userIdentity?.userName ?? null,
    userIdentityType: detail.userIdentity?.type ?? null,
    userIdentityArn: detail.userIdentity?.arn ?? detail.userIdentity?.sessionContext?.sessionIssuer?.arn ?? null,
    sourceIpAddress: detail.sourceIPAddress ?? null,
    userAgent: detail.userAgent ?? null,
    awsRegion: detail.awsRegion ?? null,
    readOnly: detail.readOnly ?? null,
    errorCode: detail.errorCode ?? null,
    errorMessage: detail.errorMessage ?? null,
    resources: (e.Resources ?? []).map((r) => ({ resourceType: r.ResourceType, resourceName: r.ResourceName })),
    requestParameters: detail.requestParameters ?? null,
    responseElements: detail.responseElements ?? null,
  };
}

/**
 * GET /api/aws-accounts/accounts/:id/cloudtrail-events — real AWS-side audit
 * history for this account, live from AWS CloudTrail's LookupEvents API
 * (not stored/synced anywhere — proxied live on every request). This is
 * genuinely different from the account's HorizonVigil activity log: it shows
 * actual AWS Console/CLI/SDK/Terraform actions taken by real IAM identities
 * (who, from what source IP, with what request parameters), not actions
 * taken through HorizonVigil itself.
 *
 * Works with zero setup on the customer's side: LookupEvents returns the
 * default 90-day CloudTrail Event History every AWS account has whether or
 * not they've configured a Trail — it just needs the connection's IAM
 * identity to have cloudtrail:LookupEvents, which the HorizonVigil
 * least-privilege policy already includes (see leastPrivilegePolicy.ts).
 * An identity without it gets a clear, actionable AccessDenied message
 * below rather than a generic 500.
 *
 * LookupAttributes is intentionally capped at one filter — that's a real
 * AWS API constraint (LookupEvents only accepts a single lookup attribute
 * per call), not something HorizonVigil is choosing to under-build.
 */
cloudtrailEventsRoutes.get('/accounts/:id/cloudtrail-events', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<ResolvableConnection[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const url = new URL(c.req.url);
    const region = url.searchParams.get('region') || connection.default_region || 'us-east-1';
    const attributeKey = url.searchParams.get('attributeKey');
    const attributeValue = url.searchParams.get('attributeValue');
    const nextToken = url.searchParams.get('nextToken');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');

    const body: Record<string, unknown> = { MaxResults: 50 };
    if (attributeKey && attributeValue && LOOKUP_ATTRIBUTE_KEYS.has(attributeKey)) {
      body.LookupAttributes = [{ AttributeKey: attributeKey, AttributeValue: attributeValue }];
    }
    // CloudTrail only retains 90 days of default Event History regardless of
    // what's requested, so an unset "from" doesn't need clamping here — AWS
    // does it for us and simply returns however much history actually exists.
    if (from) body.StartTime = Math.floor(new Date(from).getTime() / 1000);
    if (to) body.EndTime = Math.floor(new Date(to).getTime() / 1000);
    if (nextToken) body.NextToken = nextToken;

    const result = await callJsonApi(resolved.creds, {
      service: 'cloudtrail', region, host: `cloudtrail.${region}.amazonaws.com`,
      target: 'CloudTrail_20131101.LookupEvents', body,
    });

    if (!result.ok) {
      if (result.errorCode === 'AccessDeniedException' || result.status === 403) {
        return errJson(403, 'This connection\'s IAM identity doesn\'t have cloudtrail:LookupEvents permission. Grant it (already included in HorizonVigil\'s documented least-privilege policy) to see real AWS-side account activity here.');
      }
      return errJson(result.status || 500, result.errorMessage ?? result.errorCode ?? 'CloudTrail LookupEvents call failed.');
    }

    const responseBody = result.body as { Events?: RawCloudTrailEvent[]; NextToken?: string };
    return okJson({ events: (responseBody.Events ?? []).map(mapEvent), nextToken: responseBody.NextToken ?? null, region });
  }),
);
