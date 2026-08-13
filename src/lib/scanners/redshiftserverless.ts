import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const REDSHIFTSERVERLESS_RESOURCE_TYPES = ['redshift_serverless_workgroup'] as const;

interface Workgroup { workgroupName: string; workgroupArn?: string; status?: string; baseCapacity?: number; namespaceName?: string }
interface ListWorkgroupsResponse { workgroups?: Workgroup[] }

/** Redshift Serverless — a distinct API/service from classic Redshift's Query-protocol API, target prefix (RedshiftServerless) is a best-effort guess, UNVERIFIED against a real account. */
export async function scanRedshiftServerless(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'redshift-serverless', region: ctx.region, host: `redshift-serverless.${ctx.region}.amazonaws.com`,
    target: 'RedshiftServerless.ListWorkgroups', body: {},
  });
  if (!result.ok) {
    console.error(`Redshift Serverless ListWorkgroups failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const workgroups = (result.body as ListWorkgroupsResponse).workgroups ?? [];
  return workgroups.map((w) => ({
    resourceTypeKey: 'redshift_serverless_workgroup', resourceId: w.workgroupArn ?? w.workgroupName, region: ctx.region, resourceName: w.workgroupName,
    state: w.status, metadata: { baseCapacity: w.baseCapacity }, relationships: { namespaceName: w.namespaceName },
  }));
}
