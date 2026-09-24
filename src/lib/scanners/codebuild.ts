import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CodeBuild_20161006';
/** BatchGetProjects accepts at most 100 names per call. */
const BATCH_SIZE = 100;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEBUILD_RESOURCE_TYPES = ['codebuild_project'] as const;

interface EnvironmentVariable { name?: string; value?: string; type?: string }
export interface ProjectDetail {
  name: string; arn?: string; description?: string; created?: number; lastModified?: number;
  source?: { type?: string; location?: string; auth?: { type?: string } };
  secondarySources?: { type?: string; location?: string }[];
  environment?: {
    type?: string; image?: string; computeType?: string;
    privilegedMode?: boolean;
    environmentVariables?: EnvironmentVariable[];
    imagePullCredentialsType?: string;
  };
  serviceRole?: string;
  encryptionKey?: string;
  artifacts?: { type?: string; encryptionDisabled?: boolean };
  logsConfig?: { cloudWatchLogs?: { status?: string }; s3Logs?: { status?: string; encryptionDisabled?: boolean } };
  vpcConfig?: { vpcId?: string; subnets?: string[]; securityGroupIds?: string[] };
  projectVisibility?: string;
  badge?: { badgeEnabled?: boolean };
}

/** Environment variable NAMES that suggest a credential. Values are NEVER read into metadata. */
const SECRET_NAME_PATTERN = /(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|aws_access_key_id|aws_secret_access_key|access[_-]?key)/i;

/** `scheme://user[:pass]@host/…` — credentials embedded in a source URL. */
const URL_WITH_USERINFO = /^[a-z][a-z0-9+.-]*:\/\/[^/\s]*@/i;

/** The URL with any embedded credentials replaced, so it can be stored safely. */
export function redactUrl(url: string | undefined): string | null {
  if (!url) return null;
  return url.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/\s]*@/i, '$1***@');
}

/** Build-security evidence for one project (FSBP CodeBuild.1–.7). */
export function projectEvidence(p: ProjectDetail) {
  const env = p.environment ?? {};
  const plaintext = (env.environmentVariables ?? []).filter((v) => (v.type ?? 'PLAINTEXT') === 'PLAINTEXT');
  const sources = [p.source?.location, ...(p.secondarySources ?? []).map((s) => s.location)];
  return {
    description: p.description, createdAt: p.created, lastModified: p.lastModified,
    createdAtIso: toIso(p.created), lastModifiedIso: toIso(p.lastModified),
    sourceType: p.source?.type, environmentType: env.type, image: env.image, computeType: env.computeType,
    sourceLocation: redactUrl(p.source?.location),
    // CodeBuild.1: source repository URLs must not contain credentials.
    sourceLocationHasCredentials: sources.some((l) => !!l && URL_WITH_USERINFO.test(l)),
    // CodeBuild.2: no credentials in plain-text environment variables (names only).
    plaintextSecretLikeEnvNames: plaintext.map((v) => v.name).filter((n): n is string => !!n && SECRET_NAME_PATTERN.test(n)),
    // CodeBuild.5: privileged mode gives builds Docker-daemon (host root) access.
    privilegedMode: env.privilegedMode ?? false,
    // A PUBLIC_READ project exposes build logs and artifacts to anyone.
    projectVisibility: p.projectVisibility ?? 'PRIVATE',
    isPublic: p.projectVisibility === 'PUBLIC_READ',
    // CodeBuild.4 / .3 / .7: logging on, S3 logs and artifacts encrypted.
    cloudWatchLogsEnabled: p.logsConfig?.cloudWatchLogs?.status !== 'DISABLED',
    s3LogsEnabled: p.logsConfig?.s3Logs?.status === 'ENABLED',
    s3LogsEncryptionDisabled: p.logsConfig?.s3Logs?.encryptionDisabled ?? false,
    artifactsEncryptionDisabled: p.artifacts?.encryptionDisabled ?? false,
    encryptionKey: p.encryptionKey ?? null,
    inVpc: !!p.vpcConfig?.vpcId,
    badgeEnabled: p.badge?.badgeEnabled ?? false,
  };
}

const chunk = <T>(xs: T[], n: number): T[][] => Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));

/**
 * CodeBuild projects (JSON-RPC, CodeBuild_20161006).
 *
 * What changed, and why:
 *  - ListProjects paginates (nextToken), and BatchGetProjects runs in chunks
 *    of 100. The previous version silently kept the FIRST 100 projects; the
 *    101st onward looked deleted.
 *  - A failed detail batch keeps name-only rows for that chunk (as before,
 *    but per chunk) and reports the gap.
 *  - Security evidence for FSBP CodeBuild controls; URL credentials and
 *    environment-variable values are never stored.
 */
export async function scanCodeBuild(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `codebuild.${ctx.region}.amazonaws.com`;
  const list = await walkJsonRpc<string>(ctx, { service: 'codebuild', host, target: `${TARGET_PREFIX}.ListProjects`, body: {} }, 'projects', { tokenIn: 'nextToken', tokenOut: 'nextToken' });
  reportWalk(ctx, list, 'codebuild', 'ListProjects');
  const names = [...new Set(list.items.filter((n): n is string => typeof n === 'string' && n !== ''))];
  if (names.length === 0) return [];

  const batches = await mapWithConcurrency(chunk(names, BATCH_SIZE), 3, async (batch) => {
    const r = await callJsonApi(ctx.creds, { service: 'codebuild', region: ctx.region, host, target: `${TARGET_PREFIX}.BatchGetProjects`, body: { names: batch } });
    return { batch, projects: r.ok ? ((r.body as { projects?: ProjectDetail[] })?.projects ?? []) : null };
  });

  const out: ScannedResource[] = [];
  for (const { batch, projects } of batches) {
    if (projects === null) {
      console.error(`CodeBuild BatchGetProjects failed for ${batch.length} project(s) in ${ctx.region}; recording them by name only.`);
      reportListingFailure(ctx, { service: 'codebuild', action: 'BatchGetProjects', region: ctx.region });
      for (const name of batch) out.push({ resourceTypeKey: 'codebuild_project', resourceId: name, region: ctx.region, resourceName: name, metadata: { detailsCollected: false } });
      continue;
    }
    for (const p of projects) {
      if (!p?.name) continue;
      out.push({
        resourceTypeKey: 'codebuild_project', resourceId: p.arn ?? p.name, region: ctx.region, resourceName: p.name,
        metadata: { detailsCollected: true, ...projectEvidence(p) },
        relationships: {
          serviceRoleArn: p.serviceRole ?? null,
          vpcId: p.vpcConfig?.vpcId ?? null,
          subnetIds: p.vpcConfig?.subnets ?? [],
          securityGroupIds: p.vpcConfig?.securityGroupIds ?? [],
          kmsKeyArn: p.encryptionKey ?? null,
        },
      });
    }
  }
  return out;
}