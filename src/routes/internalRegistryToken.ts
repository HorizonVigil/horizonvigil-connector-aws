import { Hono, createDb, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { callJsonApi } from '../lib/awsApi';

export const internalRegistryTokenRoutes = new Hono<{ Bindings: Env }>();

/**
 * Mints a short-lived ECR registry password for cloudops-trivy — kept here
 * rather than duplicated in cloudops-trivy because this service already owns
 * every AWS credential-resolution path (access key decrypt, assume-role).
 * cloudops-trivy stays free of AWS auth logic entirely, matching the
 * "adapters around scanners, don't duplicate cloud auth" architecture.
 * Gated by the same INTERNAL_SCAN_SECRET as /internal/run-due-scans — this
 * is service-to-service only, never called from a browser.
 */
internalRegistryTokenRoutes.post('/internal/ecr-token', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured — internal service-to-service calls are not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const body = (await c.req.json().catch(() => ({}))) as { connectionId?: string; region?: string };
    if (!body.connectionId) return errJson(400, 'connectionId is required');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const rows = await db.select<ResolvableConnection[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${body.connectionId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Connection not found');

    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const region = body.region ?? connection.default_region;
    const result = await callJsonApi(resolved.creds, {
      service: 'ecr', region, host: `api.ecr.${region}.amazonaws.com`,
      target: 'AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken', body: {},
    });
    if (!result.ok) return errJson(502, `ECR GetAuthorizationToken failed: ${result.errorMessage ?? result.errorCode ?? result.status}`);

    const data = result.body as { authorizationData?: { authorizationToken: string; proxyEndpoint: string; expiresAt: number }[] };
    const entry = data.authorizationData?.[0];
    if (!entry) return errJson(502, 'ECR returned no authorization data.');

    return okJson({ authorizationToken: entry.authorizationToken, proxyEndpoint: entry.proxyEndpoint, expiresAt: entry.expiresAt });
  }),
);
