import { createApp, okJson } from '@horizonvigil/shared-lib';
import { accountsRoutes } from './routes/accounts';
import { dashboardRoutes } from './routes/dashboard';
import { orgHierarchyRoutes } from './routes/organizations';
import { permissionsRoutes } from './routes/permissions';
import { regionsRoutes } from './routes/regions';
import { costRoutes } from './routes/cost';
import { recommendationsRoutes } from './routes/recommendations';
import { recommendationsSyncRoutes } from './routes/recommendationsSync';
import { k8sCostRoutes } from './routes/k8sCost';
import { activityRoutes } from './routes/activity';
import { cloudtrailEventsRoutes } from './routes/cloudtrailEvents';
import { reportsRoutes } from './routes/reports';
import { discoveryRoutes } from './routes/discovery';
import { internalScanRoutes } from './routes/internalScan';
import { internalRegistryTokenRoutes } from './routes/internalRegistryToken';
import { remediationRoutes } from './routes/remediation';
import { isProviderRemediationEnabled, remediationDisabledResponse } from './lib/capabilities';
import { curRoutes } from './routes/cur';
import { logsRoutes } from './routes/logs';
import { bulkImportRoutes } from './routes/bulkImport';
import { identitiesRoutes } from './routes/identities';
import { healthRoutes } from './routes/health';
import { capabilityRoutes } from './routes/capabilities';

const app = createApp();

app.get('/', (c) => okJson({ service: 'connector-aws', status: 'ok' }));

app.route('/api/aws-accounts', accountsRoutes);
app.route('/api/aws-accounts', dashboardRoutes);
app.route('/api/aws-accounts', orgHierarchyRoutes);
app.route('/api/aws-accounts', permissionsRoutes);
app.route('/api/aws-accounts', regionsRoutes);
app.route('/api/aws-accounts', costRoutes);
app.route('/api/aws-accounts', recommendationsRoutes);
app.route('/api/aws-accounts', recommendationsSyncRoutes);
app.route('/api/aws-accounts', k8sCostRoutes);
app.route('/api/aws-accounts', activityRoutes);
app.route('/api/aws-accounts', cloudtrailEventsRoutes);
app.route('/api/aws-accounts', reportsRoutes);
app.route('/api/aws-accounts', discoveryRoutes);
app.route('/api/aws-accounts', internalScanRoutes);
app.route('/api/aws-accounts', internalRegistryTokenRoutes);
/**
 * Direct provider mutation is disabled in V1 (2026-09-08 production-
 * readiness audits: "No direct provider mutation ships in V1"). Denied
 * before any handler runs, so a crafted request cannot reach an AWS call
 * even if a client bypasses the UI. See lib/capabilities.ts for why the
 * whole capability is gated rather than only the mutating endpoints.
 */
app.use('/api/aws-accounts/remediation', async (c, next) => {
  if (!isProviderRemediationEnabled(c.env)) return remediationDisabledResponse();
  await next();
});
app.use('/api/aws-accounts/remediation/*', async (c, next) => {
  if (!isProviderRemediationEnabled(c.env)) return remediationDisabledResponse();
  await next();
});
app.route('/api/aws-accounts', remediationRoutes);
app.route('/api/aws-accounts', curRoutes);
app.route('/api/aws-accounts', logsRoutes);
app.route('/api/aws-accounts', bulkImportRoutes);
app.route('/api/aws-accounts', identitiesRoutes);
app.route('/api/aws-accounts', healthRoutes);
app.route('/api/aws-accounts', capabilityRoutes);


/**
 * Versioned alias for the same handlers (connector spec §23).
 *
 * `/api/aws-accounts` is kept as-is because 25 frontend call sites and four
 * Cloud Scheduler jobs point at it; renaming it would be a breaking change
 * dressed up as an improvement. `/api/v1/aws` is the contract new consumers
 * and future provider adapters should use, and gives the connector somewhere
 * to put a v2 shape later without a flag day.
 *
 * Both prefixes mount the SAME route objects, so there is no second
 * implementation to drift — including the remediation gate below, which is
 * re-registered for the versioned path so it cannot be bypassed by calling
 * the new URL.
 */
app.use('/api/v1/aws/remediation', async (c, next) => {
  if (!isProviderRemediationEnabled(c.env)) return remediationDisabledResponse();
  await next();
});
app.use('/api/v1/aws/remediation/*', async (c, next) => {
  if (!isProviderRemediationEnabled(c.env)) return remediationDisabledResponse();
  await next();
});
app.route('/api/v1/aws', accountsRoutes);
app.route('/api/v1/aws', dashboardRoutes);
app.route('/api/v1/aws', orgHierarchyRoutes);
app.route('/api/v1/aws', permissionsRoutes);
app.route('/api/v1/aws', regionsRoutes);
app.route('/api/v1/aws', costRoutes);
app.route('/api/v1/aws', recommendationsRoutes);
app.route('/api/v1/aws', recommendationsSyncRoutes);
app.route('/api/v1/aws', k8sCostRoutes);
app.route('/api/v1/aws', activityRoutes);
app.route('/api/v1/aws', cloudtrailEventsRoutes);
app.route('/api/v1/aws', reportsRoutes);
app.route('/api/v1/aws', discoveryRoutes);
app.route('/api/v1/aws', internalScanRoutes);
app.route('/api/v1/aws', internalRegistryTokenRoutes);
app.route('/api/v1/aws', remediationRoutes);
app.route('/api/v1/aws', curRoutes);
app.route('/api/v1/aws', logsRoutes);
app.route('/api/v1/aws', bulkImportRoutes);
app.route('/api/v1/aws', identitiesRoutes);
app.route('/api/v1/aws', healthRoutes);
app.route('/api/v1/aws', capabilityRoutes);

export default app;
