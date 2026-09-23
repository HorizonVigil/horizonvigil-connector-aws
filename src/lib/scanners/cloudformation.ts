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

export interface DeploymentEventRow {
  connection_id: string; provider: 'aws'; deployment_name: string; event_id: string;
  status: string; reason: string | null; resource_type: string | null;
  logical_resource_id: string | null; physical_resource_id: string | null;
  region: string; occurred_at: string; metadata: Record<string, unknown>;
}

/**
 * Real deployment history -- DescribeStackEvents returns a genuine,
 * chronological, per-resource-status log of every stack create/update/
 * delete operation, timestamped by AWS itself. This is the first real
 * deployment-tracking signal in this codebase (see the admin-console
 * investigation-infrastructure roadmap, Phase 3): every other "deployment"
 * concept anywhere in this fleet is current-state-only inventory, not
 * history.
 *
 * One DescribeStackEvents call per stack (the API has no account-wide
 * "all events" endpoint), so this is capped to the most recent 20 stacks
 * per region-scan to keep the step inside its request budget -- a
 * pragmatic first-pass limit, not a hard architectural one. No pagination
 * beyond the first page: CFN returns events newest-first, and the first
 * page is what a root-cause view actually needs (recent history), not an
 * exhaustive archive.
 */
export async function scanCloudFormationDeploymentEvents(ctx: ScannerContext, connectionId: string, stackNames: string[]): Promise<DeploymentEventRow[]> {
  const endpoint = `cloudformation.${ctx.region}.amazonaws.com`;
  const out: DeploymentEventRow[] = [];
  for (const stackName of stackNames.slice(0, 20)) {
    const result = await callQueryApi(ctx.creds, { service: 'cloudformation', region: ctx.region, host: endpoint, action: 'DescribeStackEvents', version: VERSION, params: { StackName: stackName } });
    if (!result.ok) {
      console.error(`CloudFormation DescribeStackEvents failed for ${stackName} in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      continue;
    }
    for (const event of extractListItems(extractSection(result.body as string, 'StackEvents'), 'member')) {
      const eventId = field(event, 'EventId');
      const timestamp = field(event, 'Timestamp');
      const status = field(event, 'ResourceStatus');
      if (!eventId || !timestamp || !status) continue;
      out.push({
        connection_id: connectionId, provider: 'aws', deployment_name: stackName, event_id: eventId,
        status, reason: field(event, 'ResourceStatusReason'), resource_type: field(event, 'ResourceType'),
        logical_resource_id: field(event, 'LogicalResourceId'), physical_resource_id: field(event, 'PhysicalResourceId'),
        region: ctx.region, occurred_at: timestamp,
        metadata: { clientRequestToken: field(event, 'ClientRequestToken') },
      });
    }
  }
  return out;
}
import { callQueryApi } from '../awsApi';
import { paginateQueryApi, detectQueryTruncation, incompleteSink } from '../pagination';
import { extractSection, extractListItems, field, boolField } from '../xmlList';
import { memberTexts, withoutSections } from './xmlShape';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-05-15';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDFORMATION_RESOURCE_TYPES = ['cloudformation_stack', 'cloudformation_stack_set'] as const;

/** Nested lists inside a Stack whose children reuse top-level names (Description, …). */
const STACK_NESTED = ['Parameters', 'Outputs', 'Tags', 'Capabilities', 'NotificationARNs', 'RollbackConfiguration', 'DriftInformation'];

/** CloudFormation's Query-protocol tags use `<Tags><member><Key>/<Value></member></Tags>`. */
function stackTags(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of extractListItems(extractSection(xml, 'Tags'), 'member')) {
    const key = field(tag, 'Key');
    if (key) out[key] = field(tag, 'Value') ?? '';
  }
  return out;
}

/**
 * Evidence for one stack.
 *
 * Top-level fields are read with nested lists stripped: a stack with no
 * Description used to pick up an OUTPUT's Description from the regex reader.
 * Parameters and Outputs are never stored (they can hold secrets; NoEcho
 * parameters are masked, outputs are not).
 */
export function stackEvidence(stack: string) {
  const top = withoutSections(stack, STACK_NESTED);
  const drift = extractSection(stack, 'DriftInformation') ?? '';
  return {
    metadata: {
      creationTime: field(top, 'CreationTime'),
      lastUpdatedTime: field(top, 'LastUpdatedTime'),
      description: field(top, 'Description'),
      statusReason: field(top, 'StackStatusReason'),
      // Deletion guard: deleting a stack deletes every resource it manages.
      terminationProtection: boolField(top, 'EnableTerminationProtection') ?? false,
      disableRollback: boolField(top, 'DisableRollback') ?? false,
      // IAM-capable stacks can create privileged roles.
      capabilities: memberTexts(stack, 'Capabilities'),
      // FSBP CloudFormation.1: stacks should notify an SNS topic.
      notificationArns: memberTexts(stack, 'NotificationARNs'),
      driftStatus: field(drift, 'StackDriftStatus'),
      driftCheckedAt: field(drift, 'LastCheckTimestamp'),
      isNested: !!field(top, 'ParentId'),
      parameterCount: extractListItems(extractSection(stack, 'Parameters'), 'member').length,
      outputCount: extractListItems(extractSection(stack, 'Outputs'), 'member').length,
    },
    relationships: {
      // A service role lets the stack act with permissions its caller lacks.
      roleArn: field(top, 'RoleARN'),
      parentStackId: field(top, 'ParentId'),
      rootStackId: field(top, 'RootId'),
      notificationArns: memberTexts(stack, 'NotificationARNs'),
    },
  };
}

/**
 * Stacks and StackSets (Query protocol, generic `<member>` lists).
 *
 * Both now paginate (NextToken). DescribeStacks returns 100 stacks per page;
 * the 101st used to look deleted. Incomplete walks degrade coverage through
 * the shared sink.
 */
export async function scanCloudFormation(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `cloudformation.${ctx.region}.amazonaws.com`;
  const onIncomplete = incompleteSink(ctx.creds);
  const walk = (action: string, section: string) => paginateQueryApi<string, string>(
    ctx.creds,
    { service: 'cloudformation', region: ctx.region, host, action, version: VERSION },
    (page) => extractListItems(extractSection(page, section), 'member'),
    (page) => detectQueryTruncation(page),
    { onIncomplete },
  );

  const [stacks, stackSets] = await Promise.all([walk('DescribeStacks', 'Stacks'), walk('ListStackSets', 'Summaries')]);
  for (const [action, w] of [['DescribeStacks', stacks], ['ListStackSets', stackSets]] as const) {
    if (w.termination !== 'complete') console.error(`CloudFormation ${action} in ${ctx.region} ended '${w.termination}' after ${w.pages} page(s); continuing with what was read.`);
  }

  const out: ScannedResource[] = [];
  for (const stack of stacks.items) {
    const top = withoutSections(stack, STACK_NESTED);
    const id = field(top, 'StackId');
    const name = field(top, 'StackName');
    if (!id || !name) continue;
    const evidence = stackEvidence(stack);
    out.push({
      resourceTypeKey: 'cloudformation_stack', resourceId: id, region: ctx.region, resourceName: name,
      state: field(top, 'StackStatus') ?? undefined, tags: stackTags(stack),
      metadata: evidence.metadata,
      relationships: evidence.relationships,
    });
  }
  // Stack sets are administered from a region; queried once per scan region
  // like everything else here (there is no cheaper global lookup).
  for (const ss of stackSets.items) {
    const name = field(ss, 'StackSetName');
    if (!name) continue;
    const auto = extractSection(ss, 'AutoDeployment') ?? '';
    out.push({
      resourceTypeKey: 'cloudformation_stack_set', resourceId: field(ss, 'StackSetId') ?? name, region: ctx.region, resourceName: name,
      state: field(ss, 'Status') ?? undefined,
      metadata: {
        description: field(ss, 'Description'),
        permissionModel: field(ss, 'PermissionModel'),
        driftStatus: field(ss, 'DriftStatus'),
        autoDeploymentEnabled: boolField(auto, 'Enabled') ?? null,
      },
    });
  }
  return out;
}

export interface DeploymentEventRow {
  connection_id: string; provider: 'aws'; deployment_name: string; event_id: string;
  status: string; reason: string | null; resource_type: string | null;
  logical_resource_id: string | null; physical_resource_id: string | null;
  region: string; occurred_at: string; metadata: Record<string, unknown>;
}

/** Stacks whose event history is read per region-scan. */
const MAX_EVENT_STACKS = 20;

/**
 * Deployment history -- DescribeStackEvents returns a chronological,
 * per-resource status log of every stack create/update/delete, timestamped
 * by AWS. One call per stack (no account-wide endpoint), capped at the 20
 * stacks passed first; first page only, since CloudFormation returns events
 * newest-first and recent history is what a root-cause view needs.
 * Duplicate event ids (a stack listed twice) are dropped.
 */
export async function scanCloudFormationDeploymentEvents(ctx: ScannerContext, connectionId: string, stackNames: string[]): Promise<DeploymentEventRow[]> {
  const host = `cloudformation.${ctx.region}.amazonaws.com`;
  const out: DeploymentEventRow[] = [];
  const seen = new Set<string>();
  for (const stackName of [...new Set(stackNames)].slice(0, MAX_EVENT_STACKS)) {
    const result = await callQueryApi(ctx.creds, { service: 'cloudformation', region: ctx.region, host, action: 'DescribeStackEvents', version: VERSION, params: { StackName: stackName } });
    if (!result.ok) {
      console.error(`CloudFormation DescribeStackEvents failed for ${stackName} in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      continue;
    }
    for (const event of extractListItems(extractSection(result.body as string, 'StackEvents'), 'member')) {
      const eventId = field(event, 'EventId');
      const timestamp = field(event, 'Timestamp');
      const status = field(event, 'ResourceStatus');
      if (!eventId || !timestamp || !status || seen.has(eventId)) continue;
      seen.add(eventId);
      out.push({
        connection_id: connectionId, provider: 'aws', deployment_name: stackName, event_id: eventId,
        status, reason: field(event, 'ResourceStatusReason'), resource_type: field(event, 'ResourceType'),
        logical_resource_id: field(event, 'LogicalResourceId'), physical_resource_id: field(event, 'PhysicalResourceId'),
        region: ctx.region, occurred_at: timestamp,
        metadata: { clientRequestToken: field(event, 'ClientRequestToken') },
      });
    }
  }
  return out;
}