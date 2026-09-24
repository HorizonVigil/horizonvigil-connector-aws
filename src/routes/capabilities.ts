import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, type Env } from '@horizonvigil/shared-lib';
import { AWS_CAPABILITIES, allRequiredPermissions } from '../lib/capabilityRegistry';
import { isProviderRemediationEnabled, isConnectionPurgeEnabled } from '../lib/capabilities';

export const capabilityRoutes = new Hono<{ Bindings: Env }>();

/**
 * GET /capabilities — what this connector actually supports.
 *
 * Answers §6/§28 of the connector spec at runtime rather than in a document
 * that goes stale. HorizonVigil core can use it to decide what to render for
 * an AWS connection instead of hardcoding provider assumptions, which is the
 * contract the multi-cloud adapter layer in §24 needs.
 *
 * Deliberately reports the two V1 gates as live values read from the
 * environment, not as constants: a capability page that claims remediation is
 * available while the server returns 403 would be the same false-capability
 * problem in a new place.
 */
capabilityRoutes.get('/capabilities', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    return okJson({
      provider: 'aws',
      capabilities: AWS_CAPABILITIES.map((cap) => ({
        key: cap.key,
        label: cap.label,
        awsApis: cap.awsApis,
        implemented: cap.implemented,
        probed: cap.probed,
        dataStored: cap.dataStored,
        uiConsumer: cap.uiConsumer,
        actionSupported: cap.actionSupported,
        lifecycle: cap.lifecycle,
        requiredPermissions: cap.requiredPermissions,
      })),
      /** Runtime gates, read live — never assumed. */
      gates: {
        providerRemediationEnabled: isProviderRemediationEnabled(c.env),
        connectionPurgeEnabled: isConnectionPurgeEnabled(c.env),
      },
      leastPrivilegePermissions: allRequiredPermissions(),
    });
  }),
);
