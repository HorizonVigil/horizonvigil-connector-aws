import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-12-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ELASTICBEANSTALK_RESOURCE_TYPES = ['elastic_beanstalk_application', 'elastic_beanstalk_environment'] as const;

/** Query-protocol, same shape as rds.ts — two Describe* calls, no fan-out needed since both already return every field this catalog entry uses. */
export async function scanElasticBeanstalk(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `elasticbeanstalk.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'elasticbeanstalk', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`Elastic Beanstalk ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [applications, environments] = await Promise.all([call('DescribeApplications'), call('DescribeEnvironments')]);
  const out: ScannedResource[] = [];

  for (const app of extractListItems(extractSection(applications, 'Applications'), 'member')) {
    const name = field(app, 'ApplicationName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'elastic_beanstalk_application', resourceId: name, region: ctx.region, resourceName: name,
      metadata: { description: field(app, 'Description'), dateCreated: field(app, 'DateCreated') },
    });
  }

  for (const env of extractListItems(extractSection(environments, 'Environments'), 'member')) {
    const id = field(env, 'EnvironmentId');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elastic_beanstalk_environment', resourceId: id, region: ctx.region, resourceName: field(env, 'EnvironmentName') ?? undefined,
      state: field(env, 'Status') ?? undefined,
      metadata: { health: field(env, 'Health'), cname: field(env, 'CNAME'), dateCreated: field(env, 'DateCreated'), platformArn: field(env, 'PlatformArn') },
      relationships: { applicationName: field(env, 'ApplicationName') },
    });
  }

  return out;
}
