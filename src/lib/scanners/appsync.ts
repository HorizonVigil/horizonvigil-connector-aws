import { createAwsClient } from '../awsApi';
import { fetchJson, reportWalk, walkPages } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APPSYNC_RESOURCE_TYPES = ['appsync_graphql_api'] as const;

interface LambdaAuthorizerConfig { authorizerUri?: string; authorizerResultTtlInSeconds?: number; identityValidationExpression?: string }
interface OpenIDConnectConfig { issuer?: string; clientId?: string; authTTL?: number; iatTTL?: number }
interface UserPoolConfig { userPoolId?: string; awsRegion?: string; defaultAction?: string; appIdClientRegex?: string }
interface AdditionalAuthProvider {
  authenticationType?: string;
  lambdaAuthorizerConfig?: LambdaAuthorizerConfig;
  openIDConnectConfig?: OpenIDConnectConfig;
  userPoolConfig?: UserPoolConfig;
}
interface LogConfig { cloudWatchLogsRoleArn?: string; fieldLogLevel?: string; excludeVerboseContent?: boolean }

export interface GraphqlApi {
  apiId?: string;
  apiType?: string; // "GRAPHQL" | "MERGED"
  name?: string;
  arn?: string;
  authenticationType?: string; // API_KEY | AWS_IAM | AMAZON_COGNITO_USER_POOLS | OPENID_CONNECT | AWS_LAMBDA
  additionalAuthenticationProviders?: AdditionalAuthProvider[];
  openIDConnectConfig?: OpenIDConnectConfig;
  userPoolConfig?: UserPoolConfig;
  lambdaAuthorizerConfig?: LambdaAuthorizerConfig;
  logConfig?: LogConfig;
  xrayEnabled?: boolean;
  visibility?: string; // GLOBAL | PRIVATE
  wafWebAclArn?: string;
  owner?: string;
  ownerContact?: string;
  introspectionConfig?: string; // ENABLED | DISABLED
  queryDepthLimit?: number;
  resolverCountLimit?: number;
  mergedApiExecutionRoleArn?: string;
  dns?: Record<string, string>;
  uris?: Record<string, string>;
  tags?: Record<string, string>;
}

/** API-security evidence for one GraphQL API. Facts, not verdicts. */
export function graphqlApiMetadata(api: GraphqlApi) {
  const additional = api.additionalAuthenticationProviders?.map((p) => p.authenticationType).filter((t): t is string => !!t) ?? [];
  const allAuth = [api.authenticationType, ...additional].filter((t): t is string => !!t);
  return {
    arn: api.arn,
    apiType: api.apiType,
    authenticationType: api.authenticationType,
    additionalAuthenticationTypes: additional,
    // API keys are bearer secrets with no identity; worth knowing wherever used.
    usesApiKeyAuth: allAuth.includes('API_KEY'),
    xrayEnabled: api.xrayEnabled,
    visibility: api.visibility,
    isPrivate: api.visibility === 'PRIVATE',
    wafWebAclArn: api.wafWebAclArn,
    wafProtected: !!api.wafWebAclArn,
    // Introspection defaults to ENABLED when the field is absent.
    introspectionConfig: api.introspectionConfig,
    introspectionEnabled: (api.introspectionConfig ?? 'ENABLED') === 'ENABLED',
    queryDepthLimit: api.queryDepthLimit,
    resolverCountLimit: api.resolverCountLimit,
    logFieldLogLevel: api.logConfig?.fieldLogLevel,
    loggingEnabled: !!api.logConfig?.fieldLogLevel && api.logConfig.fieldLogLevel !== 'NONE',
    owner: api.owner,
    ownerContact: api.ownerContact,
    mergedApiExecutionRoleArn: api.mergedApiExecutionRoleArn,
    uris: api.uris,
    dns: api.dns,
  };
}

/**
 * AWS AppSync (managed GraphQL APIs) — REST-JSON against the control-plane
 * host `appsync.<region>.amazonaws.com` (GET /v1/apis). Each summary already
 * carries auth, visibility, WAF, introspection and logging, so no per-API
 * call is needed.
 *
 * Now paginated (maxResults=25 is the documented page maximum; the previous
 * version stopped there, so API number 26 looked deleted). A list failure is
 * reported rather than returned as []. An API without an id is recorded with
 * an empty id -- which admission quarantines with a typed reason -- instead
 * of the old `<region>:unknown` placeholder, which gave every such API the
 * SAME identity.
 */
export async function scanAppSync(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'appsync', ctx.region);
  const base = `https://appsync.${ctx.region}.amazonaws.com`;

  const walk = await walkPages<GraphqlApi>(
    (token) => fetchJson(client, `${base}/v1/apis?maxResults=25${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`),
    (b) => b.graphqlApis,
    (b) => b.nextToken,
  );
  reportWalk(ctx, walk, 'appsync', 'ListGraphqlApis');

  return walk.items.filter(Boolean).map((api) => ({
    resourceTypeKey: 'appsync_graphql_api',
    resourceId: api.apiId ?? '',
    region: ctx.region,
    resourceName: api.name,
    tags: api.tags,
    metadata: graphqlApiMetadata(api),
    relationships: { wafWebAclArn: api.wafWebAclArn ?? null },
  }));
}