import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, boolField } from '../xmlList';
import { describeAllQuery } from './queryMarker';
import { reportListingFailure } from './scannerSupport';
import { withoutSections } from './xmlShape';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-12-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ELASTICBEANSTALK_RESOURCE_TYPES = ['elastic_beanstalk_application', 'elastic_beanstalk_environment'] as const;

const ENV_NESTED = ['Resources', 'Tier', 'EnvironmentLinks', 'OperationsRole'];

/** Evidence for one environment. */
export function environmentEvidence(env: string) {
  const top = withoutSections(env, ENV_NESTED);
  const tier = extractSection(env, 'Tier') ?? '';
  return {
    health: field(top, 'Health'), cname: field(top, 'CNAME'), dateCreated: field(top, 'DateCreated'), platformArn: field(top, 'PlatformArn'),
    // FSBP ElasticBeanstalk.1: enhanced health reporting. HealthStatus is only
    // present when enhanced health is on.
    enhancedHealthReporting: field(top, 'HealthStatus') !== null,
    healthStatus: field(top, 'HealthStatus'),
    solutionStackName: field(top, 'SolutionStackName'),
    tier: field(tier, 'Name'),
    endpointUrl: field(top, 'EndpointURL'),
    abortableOperationInProgress: boolField(top, 'AbortableOperationInProgress') ?? null,
  };
}

/**
 * Elastic Beanstalk applications and environments (Query protocol).
 *
 * What changed, and why:
 *  - DescribeEnvironments paginates (NextToken) and asks for LIVE
 *    environments only: IncludeDeleted defaults to true, so recently
 *    terminated environments were inventoried as ghosts.
 *  - Failures are reported rather than turned into an empty list.
 *  - Environment fields are read from the environment's own top level, and
 *    carry enhanced-health status, platform and tier.
 */
export async function scanElasticBeanstalk(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `elasticbeanstalk.${ctx.region}.amazonaws.com`;

  const [appsResult, envs] = await Promise.all([
    callQueryApi(ctx.creds, { service: 'elasticbeanstalk', region: ctx.region, host, action: 'DescribeApplications', version: VERSION }),
    describeAllQuery(ctx, {
      service: 'elasticbeanstalk', host, version: VERSION, action: 'DescribeEnvironments',
      params: { IncludeDeleted: 'false' }, listSection: 'Environments', itemTag: 'member',
      tokenIn: 'NextToken', tokenOut: 'NextToken', pageSizeParam: 'MaxRecords', pageSize: '1000',
    }),
  ]);

  const out: ScannedResource[] = [];
  if (!appsResult.ok) {
    console.error(`Elastic Beanstalk DescribeApplications failed in ${ctx.region} (continuing without it): ${appsResult.errorMessage ?? appsResult.errorCode ?? appsResult.status}`);
    reportListingFailure(ctx, { service: 'elasticbeanstalk', action: 'DescribeApplications', region: ctx.region, httpStatus: appsResult.status });
  } else {
    // DescribeApplications is not paginated: it returns every application.
    for (const app of extractListItems(extractSection(appsResult.body as string, 'Applications'), 'member')) {
      const top = withoutSections(app, ['Versions', 'ConfigurationTemplates', 'ResourceLifecycleConfig']);
      const name = field(top, 'ApplicationName');
      if (!name) continue;
      out.push({
        resourceTypeKey: 'elastic_beanstalk_application', resourceId: name, region: ctx.region, resourceName: name,
        metadata: { description: field(top, 'Description'), dateCreated: field(top, 'DateCreated'), applicationArn: field(top, 'ApplicationArn') },
      });
    }
  }

  for (const env of envs.items) {
    const top = withoutSections(env, ENV_NESTED);
    const id = field(top, 'EnvironmentId');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elastic_beanstalk_environment', resourceId: id, region: ctx.region, resourceName: field(top, 'EnvironmentName') ?? undefined,
      state: field(top, 'Status') ?? undefined,
      metadata: environmentEvidence(env),
      relationships: { applicationName: field(top, 'ApplicationName') },
    });
  }
  return out;
}
