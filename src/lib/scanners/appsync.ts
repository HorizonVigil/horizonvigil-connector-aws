import { createAwsClient, safeFetch } from '../awsApi';
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

interface GraphqlApi {
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
interface ListGraphqlApisResponse { graphqlApis?: GraphqlApi[]; nextToken?: string }

/**
 * AWS AppSync (managed GraphQL APIs) -- REST-JSON, confirmed via AWS's own
 * AppSync API reference (API_ListGraphqlApis.html) and the AWS General
 * Reference service-endpoints page (appsync.html): control-plane calls like
 * ListGraphqlApis go to the regional `appsync.<region>.amazonaws.com` host,
 * which is distinct from the per-API data-plane host
 * (`<apiId>.appsync-api.<region>.amazonaws.com`) that actual GraphQL
 * query/mutation traffic uses -- this scanner only ever talks to the
 * control-plane host. GET /v1/apis (optionally `?maxResults=`, `nextToken`,
 * `apiType`, `owner`) returns `{ graphqlApis: [...], nextToken }`; each
 * GraphqlApi summary already carries apiId, name, arn, authenticationType,
 * xrayEnabled, visibility, wafWebAclArn, tags, and more directly -- no
 * separate GetGraphqlApi call is needed per API, same list-is-enough shape
 * as mq.ts's ListBrokers.
 *
 * Only the first page (maxResults=25, the documented max) is fetched here --
 * acceptable for a first pass per the same reasoning as other list-only
 * scanners in this connector (mq.ts, apigateway.ts); a follow-up pass can add
 * the nextToken loop if accounts with >25 GraphQL APIs turn out to be
 * common.
 *
 * This resource type feeds this platform's API Security features (a
 * GraphQL API is a real attack surface -- open introspection, missing auth,
 * public visibility all matter there), so the field mapping here leans
 * toward preserving everything the list response already gives us
 * (authenticationType, additional auth providers, introspectionConfig,
 * visibility, wafWebAclArn, logConfig) rather than trimming to a minimal
 * set.
 *
 * UNVERIFIED against a real account's actual response shape until this runs
 * against a live connection and gets checked -- same disclosed-uncertainty
 * convention as inspector2.ts/mq.ts. The request shape (GET /v1/apis, query
 * params, host) and response field names above were checked against AWS's
 * published API reference rather than reconstructed from memory, but no live
 * AppSync API existed in any test account when this was written.
 */
export async function scanAppSync(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'appsync', ctx.region);
  const base = `https://appsync.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const res = await safeFetch(client, `${base}/v1/apis?maxResults=25`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`AppSync ListGraphqlApis failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return out;
  }

  const apis = (text ? (JSON.parse(text) as ListGraphqlApisResponse) : {}).graphqlApis ?? [];
  for (const api of apis) {
    out.push({
      resourceTypeKey: 'appsync_graphql_api',
      resourceId: api.apiId ?? api.arn ?? `${ctx.region}:unknown`,
      region: ctx.region,
      resourceName: api.name,
      tags: api.tags,
      metadata: {
        arn: api.arn,
        apiType: api.apiType,
        authenticationType: api.authenticationType,
        additionalAuthenticationTypes: api.additionalAuthenticationProviders?.map((p) => p.authenticationType).filter((t): t is string => !!t),
        xrayEnabled: api.xrayEnabled,
        visibility: api.visibility,
        wafWebAclArn: api.wafWebAclArn,
        introspectionConfig: api.introspectionConfig,
        queryDepthLimit: api.queryDepthLimit,
        resolverCountLimit: api.resolverCountLimit,
        logFieldLogLevel: api.logConfig?.fieldLogLevel,
        owner: api.owner,
        ownerContact: api.ownerContact,
        mergedApiExecutionRoleArn: api.mergedApiExecutionRoleArn,
        uris: api.uris,
        dns: api.dns,
      },
    });
  }

  return out;
}
