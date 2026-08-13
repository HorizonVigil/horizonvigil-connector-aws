import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const WORKSPACES_RESOURCE_TYPES = ['workspaces_workspace'] as const;

interface Workspace { WorkspaceId: string; DirectoryId?: string; UserName?: string; State?: string; ComputerName?: string; BundleId?: string }
interface DescribeWorkspacesResponse { Workspaces?: Workspace[] }

export async function scanWorkspaces(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'workspaces', region: ctx.region, host: `workspaces.${ctx.region}.amazonaws.com`,
    target: 'WorkspacesService.DescribeWorkspaces', body: {},
  });
  if (!result.ok) {
    console.error(`WorkSpaces DescribeWorkspaces failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const workspaces = (result.body as DescribeWorkspacesResponse).Workspaces ?? [];
  return workspaces.map((w) => ({
    resourceTypeKey: 'workspaces_workspace', resourceId: w.WorkspaceId, region: ctx.region, resourceName: w.ComputerName ?? w.UserName,
    state: w.State, metadata: { bundleId: w.BundleId, userName: w.UserName }, relationships: { directoryId: w.DirectoryId },
  }));
}
