import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DIRECTORYSERVICE_RESOURCE_TYPES = ['directory_service_directory'] as const;

interface DirectoryDescription {
  DirectoryId: string; Name?: string; Type?: string; Stage?: string; LaunchTime?: number; Size?: string; DnsIpAddrs?: string[];
}
interface DescribeDirectoriesResponse { DirectoryDescriptions?: DirectoryDescription[] }

export async function scanDirectoryService(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'ds', region: ctx.region, host: `ds.${ctx.region}.amazonaws.com`,
    target: 'DirectoryService_20150416.DescribeDirectories', body: {},
  });
  if (!result.ok) {
    console.error(`Directory Service DescribeDirectories failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const directories = (result.body as DescribeDirectoriesResponse).DirectoryDescriptions ?? [];
  return directories.map((d) => ({
    resourceTypeKey: 'directory_service_directory', resourceId: d.DirectoryId, region: ctx.region, resourceName: d.Name,
    state: d.Stage, metadata: { type: d.Type, size: d.Size, launchTime: d.LaunchTime, dnsIpAddrs: d.DnsIpAddrs },
  }));
}
