import { createAwsClient } from '../awsApi';
import { postJson, walkPages } from './restJson';
import { reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DRS_RESOURCE_TYPES = ['elastic_disaster_recovery_source_server'] as const;

export interface SourceServer {
  sourceServerID: string; arn?: string; recoveryInstanceId?: string; isArchived?: boolean;
  replicationDirection?: string;
  dataReplicationInfo?: { dataReplicationState?: string; dataReplicationError?: { error?: string } };
  lastLaunchResult?: string;
  lifeCycle?: { lastSeenByServiceDateTime?: string; lastLaunch?: { initiated?: { type?: string } } };
  sourceProperties?: { identificationHints?: { hostname?: string; awsInstanceID?: string }; os?: { fullString?: string } };
  stagingArea?: { status?: string };
  tags?: Record<string, string>;
}

/** Replication states in which the server is actually protected. */
const HEALTHY_STATES = new Set(['CONTINUOUS']);

/** Recovery-readiness evidence for one source server. */
export function sourceServerEvidence(s: SourceServer) {
  const state = s.dataReplicationInfo?.dataReplicationState;
  return {
    dataReplicationState: state ?? null,
    // A server that is not continuously replicating cannot be recovered to a recent point.
    replicationHealthy: state ? HEALTHY_STATES.has(state) : null,
    dataReplicationError: s.dataReplicationInfo?.dataReplicationError?.error ?? null,
    // Has a recovery drill or failover ever succeeded?
    lastLaunchResult: s.lastLaunchResult ?? null,
    lastLaunchType: s.lifeCycle?.lastLaunch?.initiated?.type ?? null,
    lastSeenByServiceAt: s.lifeCycle?.lastSeenByServiceDateTime ?? null,
    isArchived: s.isArchived ?? false,
    replicationDirection: s.replicationDirection ?? null,
    hostname: s.sourceProperties?.identificationHints?.hostname ?? null,
    operatingSystem: s.sourceProperties?.os?.fullString ?? null,
  };
}

/**
 * AWS Elastic Disaster Recovery source servers (REST-JSON: action-named
 * POST paths, e.g. POST /DescribeSourceServers).
 *
 * What changed, and why:
 *  - Paginates (nextToken); previously one page.
 *  - A region where DRS was never initialized answers
 *    UninitializedAccountException: that is a settled "no DRS here", not a
 *    failure, and is not reported. Any other failure IS reported, rather than
 *    returned as [] (which finalize reads as "every server deleted").
 *  - Evidence: replication health and errors, last launch (drill) result,
 *    archived state, host identity.
 */
export async function scanDrs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'drs', ctx.region);
  const walk = await walkPages<SourceServer>(
    (token) => postJson(client, `https://drs.${ctx.region}.amazonaws.com/DescribeSourceServers`, { maxResults: 300, filters: {}, ...(token ? { nextToken: token } : {}) }),
    (b) => b.items,
    (b) => b.nextToken,
  );

  if (!walk.complete) {
    const uninitialized = walk.firstPageFailed && /Uninitialized/i.test(walk.error ?? '');
    if (uninitialized) return [];
    console.error(`DRS DescribeSourceServers ${walk.firstPageFailed ? 'failed' : 'was incomplete'} in ${ctx.region}: ${walk.error ?? ''}`);
    reportListingFailure(ctx, walk.firstPageFailed
      ? { service: 'drs', action: 'DescribeSourceServers', region: ctx.region, httpStatus: walk.status }
      : { service: 'drs', action: 'DescribeSourceServers', region: ctx.region, truncated: true });
  }

  return walk.items.filter((s) => !!s?.sourceServerID).map((s) => ({
    resourceTypeKey: 'elastic_disaster_recovery_source_server', resourceId: s.arn ?? s.sourceServerID, region: ctx.region,
    resourceName: s.sourceProperties?.identificationHints?.hostname ?? s.sourceServerID,
    state: s.dataReplicationInfo?.dataReplicationState,
    tags: s.tags,
    metadata: sourceServerEvidence(s),
    relationships: {
      recoveryInstanceId: s.recoveryInstanceId,
      sourceInstanceId: s.sourceProperties?.identificationHints?.awsInstanceID ?? null,
    },
  }));
}
