import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CodePipeline_20150709';
/** GetPipeline follow-ups per region. */
const MAX_PIPELINE_DETAILS = 25;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEPIPELINE_RESOURCE_TYPES = ['codepipeline_pipeline'] as const;

interface PipelineSummary { name: string; version?: number; created?: number; updated?: number; pipelineType?: string; executionMode?: string }
interface ActionDeclaration { name?: string; actionTypeId?: { category?: string; owner?: string; provider?: string; version?: string }; roleArn?: string }
export interface PipelineDeclaration {
  name?: string; roleArn?: string; pipelineType?: string; executionMode?: string;
  artifactStore?: { type?: string; location?: string; encryptionKey?: { id?: string; type?: string } };
  artifactStores?: Record<string, { location?: string; encryptionKey?: { id?: string } }>;
  stages?: { name?: string; actions?: ActionDeclaration[] }[];
}

/** Supply-chain evidence from GetPipeline; `detailsCollected: false` means NOT_ASSESSED. */
export function pipelineEvidence(p: PipelineDeclaration | null) {
  if (!p) return { detailsCollected: false };
  const actions = (p.stages ?? []).flatMap((s) => s.actions ?? []);
  const sources = actions.filter((a) => a.actionTypeId?.category === 'Source');
  const stores = [p.artifactStore, ...Object.values(p.artifactStores ?? {})].filter(Boolean);
  return {
    detailsCollected: true,
    stageCount: p.stages?.length ?? 0,
    actionCount: actions.length,
    sourceProviders: [...new Set(sources.map((a) => a.actionTypeId?.provider).filter((v): v is string => !!v))],
    // GitHub "version 1" source actions authenticate with a stored OAuth
    // token; AWS deprecates them in favour of CodeStar/CodeConnections.
    usesGitHubV1OAuth: sources.some((a) => a.actionTypeId?.owner === 'ThirdParty' && a.actionTypeId?.provider === 'GitHub'),
    // Artifacts are encrypted with the AWS-managed S3 key unless a customer key is set.
    artifactStoreCustomerKms: stores.length > 0 && stores.every((s) => !!s?.encryptionKey?.id),
    manualApprovalCount: actions.filter((a) => a.actionTypeId?.category === 'Approval').length,
    actionRoleArns: [...new Set(actions.map((a) => a.roleArn).filter((v): v is string => !!v))],
  };
}

/**
 * CodePipeline pipelines (JSON-RPC, CodePipeline_20150709).
 *
 * ListPipelines paginates now (nextToken); failures are reported. Each
 * pipeline carries supply-chain evidence from a bounded GetPipeline pass:
 * service role, source providers (and deprecated GitHub v1 OAuth sources),
 * artifact-store encryption and manual approval gates.
 */
export async function scanCodePipeline(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `codepipeline.${ctx.region}.amazonaws.com`;
  const list = await walkJsonRpc<PipelineSummary>(ctx, { service: 'codepipeline', host, target: `${TARGET_PREFIX}.ListPipelines`, body: { maxResults: 1000 } }, 'pipelines', { tokenIn: 'nextToken', tokenOut: 'nextToken' });
  reportWalk(ctx, list, 'codepipeline', 'ListPipelines');
  const pipelines = list.items.filter((p) => !!p?.name);

  const details = new Map<string, PipelineDeclaration | null>();
  await mapWithConcurrency(pipelines.slice(0, MAX_PIPELINE_DETAILS), 4, async (p) => {
    const r = await callJsonApi(ctx.creds, { service: 'codepipeline', region: ctx.region, host, target: `${TARGET_PREFIX}.GetPipeline`, body: { name: p.name } });
    details.set(p.name, r.ok ? ((r.body as { pipeline?: PipelineDeclaration })?.pipeline ?? null) : null);
  });

  return pipelines.map((p) => {
    const d = details.get(p.name) ?? null;
    return {
      resourceTypeKey: 'codepipeline_pipeline', resourceId: p.name, region: ctx.region, resourceName: p.name,
      metadata: {
        version: p.version, createdAt: p.created, updatedAt: p.updated,
        createdAtIso: toIso(p.created), updatedAtIso: toIso(p.updated),
        pipelineType: p.pipelineType ?? d?.pipelineType ?? null,
        executionMode: p.executionMode ?? d?.executionMode ?? null,
        ...pipelineEvidence(d),
      },
      relationships: {
        roleArn: d?.roleArn ?? null,
        artifactBucket: d?.artifactStore?.location ?? null,
        artifactKmsKeyId: d?.artifactStore?.encryptionKey?.id ?? null,
      },
    };
  });
}