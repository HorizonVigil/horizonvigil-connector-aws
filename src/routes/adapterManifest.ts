import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { buildManifest, validateManifest } from '../lib/adapterContract';

export const adapterManifestRoutes = new Hono<{ Bindings: Env }>();

/**
 * GET /adapter-manifest — AWS-00.
 *
 * The machine-readable capability manifest, derived from the capability
 * registry rather than declared separately, so it cannot drift from what the
 * connector actually implements.
 *
 * Authenticated: the manifest names IAM actions and the internal tables each
 * capability writes. That is not secret, but it describes this deployment's
 * surface and there is no reason to hand it to an unauthenticated caller.
 *
 * Deliberately NOT org-scoped beyond membership — the manifest describes the
 * adapter build, not a tenant's data, and is identical for every org on this
 * revision.
 */
adapterManifestRoutes.get('/adapter-manifest', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const manifest = buildManifest();
    const issues = validateManifest(manifest);

    /**
     * A manifest that fails its own validation is not served as if it were
     * fine. Returning it with a 200 would make the invalid declaration the
     * thing other systems trust — which is precisely what validation exists
     * to prevent.
     */
    if (issues.length > 0) {
      return errJson(500, `Adapter manifest failed validation: ${issues.map((i) => `${i.capability}: ${i.problem}`).join('; ')}`);
    }

    return okJson(manifest);
  }),
);
