import { createApp, okJson } from '@horizonvigil/shared-lib';
import { accountsRoutes } from './routes/accounts';
import { dashboardRoutes } from './routes/dashboard';
import { orgHierarchyRoutes } from './routes/organizations';
import { permissionsRoutes } from './routes/permissions';
import { regionsRoutes } from './routes/regions';
import { costRoutes } from './routes/cost';
import { recommendationsRoutes } from './routes/recommendations';
import { recommendationsSyncRoutes } from './routes/recommendationsSync';
import { activityRoutes } from './routes/activity';
import { cloudtrailEventsRoutes } from './routes/cloudtrailEvents';
import { reportsRoutes } from './routes/reports';
import { discoveryRoutes } from './routes/discovery';
import { internalScanRoutes } from './routes/internalScan';
import { internalRegistryTokenRoutes } from './routes/internalRegistryToken';
import { remediationRoutes } from './routes/remediation';
import { curRoutes } from './routes/cur';
import { logsRoutes } from './routes/logs';
import { bulkImportRoutes } from './routes/bulkImport';
import { identitiesRoutes } from './routes/identities';
import { healthRoutes } from './routes/health';

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
app.route('/api/aws-accounts', activityRoutes);
app.route('/api/aws-accounts', cloudtrailEventsRoutes);
app.route('/api/aws-accounts', reportsRoutes);
app.route('/api/aws-accounts', discoveryRoutes);
app.route('/api/aws-accounts', internalScanRoutes);
app.route('/api/aws-accounts', internalRegistryTokenRoutes);
app.route('/api/aws-accounts', remediationRoutes);
app.route('/api/aws-accounts', curRoutes);
app.route('/api/aws-accounts', logsRoutes);
app.route('/api/aws-accounts', bulkImportRoutes);
app.route('/api/aws-accounts', identitiesRoutes);
app.route('/api/aws-accounts', healthRoutes);

export default app;
