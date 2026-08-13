import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const IMAGEBUILDER_RESOURCE_TYPES = ['image_builder_pipeline'] as const;

interface ImagePipeline { arn: string; name?: string; status?: string; platform?: string; dateCreated?: string }
interface ListImagePipelinesResponse { imagePipelineList?: ImagePipeline[] }

/** EC2 Image Builder — REST-JSON, POST /listImagePipelines. UNVERIFIED against a real account. */
export async function scanImageBuilder(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'imagebuilder', ctx.region);
  const res = await client.fetch(`https://imagebuilder.${ctx.region}.amazonaws.com/listImagePipelines`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Image Builder ListImagePipelines failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const pipelines = ((text ? JSON.parse(text) : {}) as ListImagePipelinesResponse).imagePipelineList ?? [];
  return pipelines.map((p) => ({
    resourceTypeKey: 'image_builder_pipeline', resourceId: p.arn, region: ctx.region, resourceName: p.name,
    state: p.status, metadata: { platform: p.platform, dateCreated: p.dateCreated },
  }));
}
