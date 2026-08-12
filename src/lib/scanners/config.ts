import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CONFIG_RESOURCE_TYPES = ['config_recorder', 'config_rule', 'config_conformance_pack'] as const;

interface ConfigurationRecorder { name: string; roleARN?: string; recordingGroup?: { allSupported?: boolean } }
interface DescribeRecordersResponse { ConfigurationRecorders?: ConfigurationRecorder[] }
interface RecorderStatus { name: string; recording?: boolean; lastStatus?: string }
interface DescribeRecorderStatusResponse { ConfigurationRecordersStatus?: RecorderStatus[] }
interface ConfigRule { ConfigRuleName: string; ConfigRuleArn?: string; ConfigRuleId?: string; Description?: string; ConfigRuleState?: string; Source?: { Owner?: string; SourceIdentifier?: string } }
interface DescribeRulesResponse { ConfigRules?: ConfigRule[] }
interface ConformancePack { ConformancePackName: string; ConformancePackArn?: string; ConformancePackId?: string; CreatedBy?: string }
interface DescribeConformancePacksResponse { ConformancePackDetails?: ConformancePack[] }

/**
 * AWS Config — same JSON 1.1 target-header protocol + target prefix
 * (StarlingDoveService) as awsConfigFindings.ts, which already exercises
 * this exact host/protocol for compliance evaluations. Config recorders are
 * account/region singletons (0 or 1 per region), rules and conformance
 * packs can be many; all three are simple list-only inventory here, no
 * per-rule compliance detail (that's what awsConfigFindings.ts already
 * covers via a separate finding-shaped path).
 */
export async function scanConfig(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `config.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'config', region: ctx.region, host, target: `StarlingDoveService.${target}`, body });

  const out: ScannedResource[] = [];

  const recordersResult = await call('DescribeConfigurationRecorders');
  if (!recordersResult.ok) {
    console.error(`AWS Config DescribeConfigurationRecorders failed in ${ctx.region} (continuing without it — likely just not set up there): ${recordersResult.errorMessage ?? recordersResult.errorCode ?? recordersResult.status}`);
    return out;
  }
  const recorders = (recordersResult.body as DescribeRecordersResponse).ConfigurationRecorders ?? [];
  let statusByName = new Map<string, RecorderStatus>();
  if (recorders.length > 0) {
    const statusResult = await call('DescribeConfigurationRecorderStatus');
    if (statusResult.ok) {
      statusByName = new Map(((statusResult.body as DescribeRecorderStatusResponse).ConfigurationRecordersStatus ?? []).map((s) => [s.name, s]));
    }
  }
  for (const r of recorders) {
    const status = statusByName.get(r.name);
    out.push({
      resourceTypeKey: 'config_recorder', resourceId: `${ctx.region}:${r.name}`, region: ctx.region, resourceName: r.name,
      state: status?.recording ? 'recording' : 'stopped', metadata: { roleArn: r.roleARN, allSupported: r.recordingGroup?.allSupported, lastStatus: status?.lastStatus },
    });
  }

  const rulesResult = await call('DescribeConfigRules');
  for (const rule of (rulesResult.ok ? (rulesResult.body as DescribeRulesResponse).ConfigRules : []) ?? []) {
    out.push({
      resourceTypeKey: 'config_rule', resourceId: rule.ConfigRuleArn ?? `${ctx.region}:${rule.ConfigRuleName}`, region: ctx.region, resourceName: rule.ConfigRuleName,
      state: rule.ConfigRuleState, metadata: { description: rule.Description, sourceOwner: rule.Source?.Owner, sourceIdentifier: rule.Source?.SourceIdentifier },
    });
  }

  const packsResult = await call('DescribeConformancePacks');
  for (const pack of (packsResult.ok ? (packsResult.body as DescribeConformancePacksResponse).ConformancePackDetails : []) ?? []) {
    out.push({
      resourceTypeKey: 'config_conformance_pack', resourceId: pack.ConformancePackArn ?? `${ctx.region}:${pack.ConformancePackName}`, region: ctx.region, resourceName: pack.ConformancePackName,
      metadata: { createdBy: pack.CreatedBy },
    });
  }

  return out;
}
