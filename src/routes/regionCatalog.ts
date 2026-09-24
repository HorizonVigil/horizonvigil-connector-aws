import { Hono, createDb, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { loadConnection } from './discovery';
import { resolveCredentials } from './permissions';
import { describeRegions } from '../lib/regionCatalog';

export const regionCatalogRoutes = new Hono<{ Bindings: Env }>();

/**
 * POST /internal/refresh-region-catalog — AWS-05.
 *
 * Populates `provider_regions` from `ec2:DescribeRegions` rather than from
 * observation. The catalog currently holds 17 rows, every one with
 * `opt_in_required = NULL` and `status = UNKNOWN`, because it was seeded by
 * looking at which regions already had resources: that proves a region
 * exists and proves nothing about whether the account may use it.
 *
 * Runs per connection because opt-in status is an ACCOUNT fact, not a global
 * one. Two accounts see different answers for the same region, which is
 * precisely why a hardcoded roster cannot be right for everyone.
 *
 * Written under the service role: the catalog is provider fact readable by
 * any member, and only the server may write it.
 */
regionCatalogRoutes.post('/internal/refresh-region-catalog', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured — region catalog refresh is not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured — region catalog refresh cannot authenticate to the database.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);

    const connections = await db.select<{ id: string; org_id: string; connection_name: string }[]>('cloud_connections', {
      select: 'id,org_id,connection_name',
      filters: { provider: 'eq.aws', status: 'eq.connected' },
      limit: 50,
    });

    const results: unknown[] = [];
    for (const row of connections) {
      const connection = await loadConnection(db, row.org_id, null, row.id);
      if (!connection) continue;

      const resolved = await resolveCredentials(c.env, connection as never);
      if ('error' in resolved) {
        // A connection whose credentials will not resolve tells us nothing
        // about regions. Recorded as skipped rather than written as an empty
        // or UNKNOWN catalog, which would overwrite good rows with nothing.
        results.push({ connectionId: row.id, skipped: 'credentials_unavailable' });
        continue;
      }

      const probe = await describeRegions(resolved.creds, connection.default_region ?? 'us-east-1');
      if (!probe.ok) {
        results.push({ connectionId: row.id, error: probe.error });
        continue;
      }

      const observedAt = new Date().toISOString();

      /**
       * Two tables, because these are two different kinds of fact.
       *
       * Region EXISTENCE is provider fact: us-east-1 exists for everyone.
       * Region OPT-IN is ACCOUNT fact: whether this account may use
       * ap-east-1 says nothing about any other account.
       *
       * Conflating them is not hypothetical — the first run of this endpoint
       * against two production accounts returned 18 available versus 17, and
       * the second write overwrote the first, leaving one account's view
       * presented as global truth.
       */
      const existenceRows = probe.regions.map((r) => ({
        provider: 'aws',
        partition: r.partition,
        region_code: r.regionCode,
        // Provider-level: the region exists and is reachable. Whether THIS
        // account has opted in is recorded per connection below.
        status: 'AVAILABLE',
        // Whether the region requires opt-in at all is a provider fact;
        // whether an account has done so is not.
        opt_in_required: r.optInRequired,
        source: 'describe_regions',
        observed_at: observedAt,
        updated_at: observedAt,
      }));

      const optInRows = probe.regions.map((r) => ({
        org_id: row.org_id,
        connection_id: row.id,
        partition: r.partition,
        region_code: r.regionCode,
        status: r.status,
        opt_in_required: r.optInRequired,
        provider_opt_in_status: r.optInStatus,
        source: 'describe_regions',
        observed_at: observedAt,
        updated_at: observedAt,
      }));

      await db.insert(
        'provider_regions?on_conflict=provider,partition,region_code',
        existenceRows,
        'resolution=merge-duplicates,return=minimal',
      );
      await db.insert(
        'connection_region_opt_in?on_conflict=connection_id,region_code',
        optInRows,
        'resolution=merge-duplicates,return=minimal',
      );

      results.push({
        connectionId: row.id,
        regions: existenceRows.length,
        available: probe.regions.filter((r) => r.status === 'AVAILABLE').length,
        notOptedIn: probe.regions.filter((r) => r.status === 'NOT_OPTED_IN').length,
        unknown: probe.regions.filter((r) => r.status === 'UNKNOWN').length,
      });
    }

    return okJson({ connectionsProbed: results.length, results });
  }),
);
