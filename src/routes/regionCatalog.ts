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
      const rows = probe.regions.map((r) => ({
        provider: 'aws',
        partition: r.partition,
        region_code: r.regionCode,
        status: r.status,
        opt_in_required: r.optInRequired,
        source: 'describe_regions',
        observed_at: observedAt,
        updated_at: observedAt,
      }));

      /**
       * Upsert on the catalog's identity. `describe_regions` rows overwrite
       * `observed` ones, which is the point — an inferred row should yield to
       * the provider's own answer the moment one exists.
       */
      await db.insert(
        'provider_regions?on_conflict=provider,partition,region_code',
        rows,
        'resolution=merge-duplicates,return=minimal',
      );

      results.push({
        connectionId: row.id,
        regions: rows.length,
        available: probe.regions.filter((r) => r.status === 'AVAILABLE').length,
        notOptedIn: probe.regions.filter((r) => r.status === 'NOT_OPTED_IN').length,
        unknown: probe.regions.filter((r) => r.status === 'UNKNOWN').length,
      });
    }

    return okJson({ connectionsProbed: results.length, results });
  }),
);
