import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-05-15';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDFORMATION_RESOURCE_TYPES = ['cloudformation_stack', 'cloudformation_stack_set'] as const;

/** CloudFormation's Query-protocol tags use `<Tags><member><Key>/<Value></member></Tags>`, same shape as Auto Scaling's. */
function stackTags(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of extractListItems(extractSection(xml, 'Tags'), 'member')) {
    const key = field(tag, 'Key');
    if (key) out[key] = field(tag, 'Value') ?? '';
  }
  return out;
}

/** Stacks and StackSets — one signer, 2 Query-protocol calls. CloudFormation repeats the generic `<member>` tag, like EC2/IAM/SNS, not RDS/ElastiCache/Redshift's named-tag convention. */
export async function scanCloudFormation(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `cloudformation.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'cloudformation', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`CloudFormation ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [stacks, stackSets] = await Promise.all([call('DescribeStacks'), call('ListStackSets')]);

  const out: ScannedResource[] = [];
  for (const stack of extractListItems(extractSection(stacks, 'Stacks'), 'member')) {
    const id = field(stack, 'StackId');
    const name = field(stack, 'StackName');
    if (!id || !name) continue;
    out.push({
      resourceTypeKey: 'cloudformation_stack', resourceId: id, region: ctx.region, resourceName: name,
      state: field(stack, 'StackStatus') ?? undefined, tags: stackTags(stack),
      metadata: { creationTime: field(stack, 'CreationTime'), description: field(stack, 'Description') },
    });
  }
  // Stack sets are account/region-scoped by their admin account's region,
  // not per-resource-region like stacks — still queried once per scan
  // region like everything else here, since a stack set can be administered
  // from any region and there's no cheaper global lookup for it.
  for (const ss of extractListItems(extractSection(stackSets, 'Summaries'), 'member')) {
    const name = field(ss, 'StackSetName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'cloudformation_stack_set', resourceId: field(ss, 'StackSetId') ?? name, region: ctx.region, resourceName: name,
      state: field(ss, 'Status') ?? undefined, metadata: { description: field(ss, 'Description') },
    });
  }
  return out;
}
