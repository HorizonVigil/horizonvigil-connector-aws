import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CONFIG_RESOURCE_TYPES = ['config_recorder', 'config_rule', 'config_conformance_pack'] as const;

interface ConfigurationRecorder {
  name: string; roleARN?: string;
  recordingGroup?: {
    allSupported?: boolean; includeGlobalResourceTypes?: boolean; resourceTypes?: string[];
    exclusionByResourceTypes?: { resourceTypes?: string[] }; recordingStrategy?: { useOnly?: string };
  };
  recordingMode?: { recordingFrequency?: string };
  servicePrincipal?: string;
}
interface RecorderStatus {
  name: string; recording?: boolean; lastStatus?: string; lastErrorCode?: string; lastErrorMessage?: string;
  lastStartTime?: number; lastStopTime?: number; lastStatusChangeTime?: number;
}
interface DeliveryChannel { name?: string; s3BucketName?: string; snsTopicARN?: string; s3KmsKeyArn?: string }
interface ConfigRule {
  ConfigRuleName: string; ConfigRuleArn?: string; ConfigRuleId?: string; Description?: string; ConfigRuleState?: string;
  Source?: { Owner?: string; SourceIdentifier?: string }; MaximumExecutionFrequency?: string; CreatedBy?: string;
}
interface ConformancePack { ConformancePackName: string; ConformancePackArn?: string; ConformancePackId?: string; CreatedBy?: string; LastUpdateRequestedTime?: number }

const JSON11 = 'StarlingDoveService';

/** Recording-scope evidence for one recorder (CIS 3.3: record all resources, in every region). */
export function recorderEvidence(r: ConfigurationRecorder, status: RecorderStatus | undefined, statusCollected: boolean, channel: DeliveryChannel | undefined) {
  const group = r.recordingGroup ?? {};
  return {
    state: !statusCollected ? undefined : status?.recording ? 'recording' : 'stopped',
    metadata: {
      roleArn: r.roleARN,
      allSupported: group.allSupported,
      includeGlobalResourceTypes: group.includeGlobalResourceTypes ?? null,
      recordingStrategy: group.recordingStrategy?.useOnly ?? null,
      excludedResourceTypes: group.exclusionByResourceTypes?.resourceTypes ?? [],
      recordingFrequency: r.recordingMode?.recordingFrequency ?? null,
      serviceLinked: !!r.servicePrincipal,
      statusCollected,
      recording: statusCollected ? (status?.recording ?? false) : null,
      lastStatus: status?.lastStatus,
      lastErrorCode: status?.lastErrorCode ?? null,
      lastStatusChangeIso: toIso(status?.lastStatusChangeTime),
      // Where configuration history goes; no channel means nothing is delivered.
      deliveryChannelConfigured: !!channel,
      deliveryS3BucketName: channel?.s3BucketName ?? null,
      deliverySnsTopicArn: channel?.snsTopicARN ?? null,
      deliveryS3KmsKeyArn: channel?.s3KmsKeyArn ?? null,
    },
  };
}

/**
 * AWS Config inventory: recorders, rules and conformance packs (JSON 1.1,
 * StarlingDoveService — the same protocol awsConfigFindings.ts uses).
 *
 * What changed, and why:
 *  - A recorder whose STATUS could not be read was reported as 'stopped' --
 *    a false "Config is off" finding. Its state is now unknown.
 *  - DescribeConfigRules (25 per page) and DescribeConformancePacks
 *    paginate; previously page one only, so rule number 26 looked deleted.
 *    A recorder-list failure no longer skips rules and packs.
 *  - Failures are reported rather than returned as [].
 *  - Recorders carry their recording scope (all resources, global types,
 *    exclusions, frequency) and delivery channel (S3/SNS/KMS).
 */
export async function scanConfig(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `config.${ctx.region}.amazonaws.com`;
  const call = (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'config', region: ctx.region, host, target: `${JSON11}.${target}`, body });

  const [recordersResult, statusResult, channelsResult, rules, packs] = await Promise.all([
    call('DescribeConfigurationRecorders'),
    call('DescribeConfigurationRecorderStatus'),
    call('DescribeDeliveryChannels'),
    walkJsonRpc<ConfigRule>(ctx, { service: 'config', host, target: `${JSON11}.DescribeConfigRules`, body: {} }, 'ConfigRules'),
    walkJsonRpc<ConformancePack>(ctx, { service: 'config', host, target: `${JSON11}.DescribeConformancePacks`, body: { Limit: 20 } }, 'ConformancePackDetails'),
  ]);
  reportWalk(ctx, rules, 'config', 'DescribeConfigRules');
  reportWalk(ctx, packs, 'config', 'DescribeConformancePacks');

  const out: ScannedResource[] = [];

  if (!recordersResult.ok) {
    console.error(`AWS Config DescribeConfigurationRecorders failed in ${ctx.region} (continuing without it): ${recordersResult.errorMessage ?? recordersResult.errorCode ?? recordersResult.status}`);
    reportListingFailure(ctx, { service: 'config', action: 'DescribeConfigurationRecorders', region: ctx.region, httpStatus: recordersResult.status });
  } else {
    const recorders = (recordersResult.body as { ConfigurationRecorders?: ConfigurationRecorder[] })?.ConfigurationRecorders ?? [];
    const statusByName = new Map(((statusResult.ok ? (statusResult.body as { ConfigurationRecordersStatus?: RecorderStatus[] })?.ConfigurationRecordersStatus : []) ?? []).map((s) => [s.name, s]));
    const channels = (channelsResult.ok ? (channelsResult.body as { DeliveryChannels?: DeliveryChannel[] })?.DeliveryChannels : []) ?? [];
    for (const r of recorders) {
      if (!r?.name) continue;
      const e = recorderEvidence(r, statusByName.get(r.name), statusResult.ok, channels[0]);
      out.push({
        resourceTypeKey: 'config_recorder', resourceId: `${ctx.region}:${r.name}`, region: ctx.region, resourceName: r.name,
        state: e.state, metadata: e.metadata,
        relationships: { roleArn: r.roleARN ?? null, deliveryS3BucketName: channels[0]?.s3BucketName ?? null },
      });
    }
  }

  for (const rule of rules.items) {
    if (!rule?.ConfigRuleName) continue;
    out.push({
      resourceTypeKey: 'config_rule', resourceId: rule.ConfigRuleArn ?? `${ctx.region}:${rule.ConfigRuleName}`, region: ctx.region, resourceName: rule.ConfigRuleName,
      state: rule.ConfigRuleState,
      metadata: {
        description: rule.Description, sourceOwner: rule.Source?.Owner, sourceIdentifier: rule.Source?.SourceIdentifier,
        maximumExecutionFrequency: rule.MaximumExecutionFrequency ?? null,
        createdBy: rule.CreatedBy ?? null,
      },
    });
  }

  for (const pack of packs.items) {
    if (!pack?.ConformancePackName) continue;
    out.push({
      resourceTypeKey: 'config_conformance_pack', resourceId: pack.ConformancePackArn ?? `${ctx.region}:${pack.ConformancePackName}`, region: ctx.region, resourceName: pack.ConformancePackName,
      metadata: { createdBy: pack.CreatedBy, lastUpdateRequestedIso: toIso(pack.LastUpdateRequestedTime) },
    });
  }

  return out;
}