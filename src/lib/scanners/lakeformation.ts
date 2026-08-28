import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const LAKEFORMATION_RESOURCE_TYPES = ['lake_formation_permission'] as const;

interface DataLakePrincipal { DataLakePrincipalIdentifier?: string }

/** The many possible resource shapes ListPermissions can grant on — exactly one of these keys is set per item. */
interface LfResource {
  Catalog?: { Id?: string };
  Database?: { Name?: string };
  Table?: { DatabaseName?: string; Name?: string };
  TableWithColumns?: { DatabaseName?: string; Name?: string };
  DataCellsFilter?: { DatabaseName?: string; TableName?: string; Name?: string };
  DataLocation?: { ResourceArn?: string };
  LFTag?: { TagKey?: string; TagValues?: string[] };
  LFTagPolicy?: { ExpressionName?: string; ResourceType?: string };
  LFTagExpression?: { Name?: string };
}

interface PrincipalResourcePermission {
  Principal?: DataLakePrincipal;
  Resource?: LfResource;
  Permissions?: string[];
  PermissionsWithGrantOption?: string[];
  AdditionalDetails?: { ResourceShare?: string[] };
  LastUpdated?: number;
  LastUpdatedBy?: string;
}
interface ListPermissionsResponse { PrincipalResourcePermissions?: PrincipalResourcePermission[]; NextToken?: string }

/**
 * Reduces the many possible `Resource` union shapes ListPermissions can
 * return down to a stable (kind, label) pair. Permission grants have no ARN
 * or ID of their own, so this is used to build a synthetic resourceId/name.
 */
function describeResource(r: LfResource | undefined): { kind: string; label: string } {
  if (!r) return { kind: 'unknown', label: 'unknown' };
  if (r.Catalog) return { kind: 'catalog', label: r.Catalog.Id ?? 'default' };
  if (r.Database) return { kind: 'database', label: r.Database.Name ?? 'unknown' };
  if (r.TableWithColumns) return { kind: 'table_with_columns', label: `${r.TableWithColumns.DatabaseName ?? '?'}.${r.TableWithColumns.Name ?? '?'}` };
  if (r.Table) return { kind: 'table', label: `${r.Table.DatabaseName ?? '?'}.${r.Table.Name ?? '?'}` };
  if (r.DataCellsFilter) return { kind: 'data_cells_filter', label: `${r.DataCellsFilter.DatabaseName ?? '?'}.${r.DataCellsFilter.TableName ?? '?'}.${r.DataCellsFilter.Name ?? '?'}` };
  if (r.DataLocation) return { kind: 'data_location', label: r.DataLocation.ResourceArn ?? 'unknown' };
  if (r.LFTag) return { kind: 'lf_tag', label: `${r.LFTag.TagKey ?? '?'}=${(r.LFTag.TagValues ?? []).join(',')}` };
  if (r.LFTagPolicy) return { kind: 'lf_tag_policy', label: r.LFTagPolicy.ExpressionName ?? r.LFTagPolicy.ResourceType ?? 'unknown' };
  if (r.LFTagExpression) return { kind: 'lf_tag_expression', label: r.LFTagExpression.Name ?? 'unknown' };
  return { kind: 'unknown', label: 'unknown' };
}

/**
 * Lake Formation fine-grained data permissions -- who (Principal) can do
 * what (Permissions) on which catalog/database/table/tag resource.
 *
 * Deviates from this scanner's original brief: Lake Formation's
 * ListPermissions is a REST-JSON operation (`POST /ListPermissions`, plain
 * JSON body, no `X-Amz-Target` header/target-prefix at all), *not* the
 * JSON-RPC 1.1 protocol athena.ts/ce.ts use -- confirmed against botocore's
 * `lakeformation/2017-03-31/service-2.json` (`"protocol": "rest-json"`) and
 * the AWS SDK JS v3 `client-lakeformation` package shipping an
 * `Aws_restJson1.ts` protocol module, not an `Aws_json1_1.ts` one. So this
 * goes through `createAwsClient`/`safeFetch` directly, the same REST-JSON
 * family as inspector2.ts/accessanalyzer.ts, rather than `callJsonApi`.
 *
 * A permission grant has no ARN or ID of its own, so resourceId is a
 * synthetic composite of principal + a resource description + region (see
 * describeResource above). Called with no Principal/Resource/ResourceType
 * filter, so it returns every explicitly-granted permission the caller can
 * see account-wide; paginated via NextToken (capped at 20 pages / up to
 * 20,000 grants as a sanity limit against a pathological account, not a
 * real expected ceiling). Regional, like Inspector2/GuardDuty/Security Hub
 * -- not registered as account-wide/global.
 *
 * Many AWS accounts have never opted into Lake Formation at all, in which
 * case this call fails (e.g. AccessDeniedException / EntityNotFoundException
 * style errors) or simply returns an empty list -- both are treated as the
 * normal, honest "not set up" outcome here, same as every other
 * optional-service scanner in this connector, not a bug.
 *
 * UNVERIFIED against a real account's actual Lake Formation response shape
 * until this runs against a live connection and gets checked -- same
 * disclosed-uncertainty convention as inspector2.ts.
 */
export async function scanLakeFormation(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'lakeformation', ctx.region);
  const base = `https://lakeformation.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  let nextToken: string | undefined;
  let page = 0;
  do {
    const res = await safeFetch(client, `${base}/ListPermissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ MaxResults: 1000, ...(nextToken ? { NextToken: nextToken } : {}) }),
    });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Lake Formation ListPermissions failed in ${ctx.region} (continuing without it -- likely just not opted into Lake Formation there): HTTP ${res.status} ${text.slice(0, 200)}`);
      break;
    }

    const body = (text ? JSON.parse(text) : {}) as ListPermissionsResponse;
    for (const p of body.PrincipalResourcePermissions ?? []) {
      const principalId = p.Principal?.DataLakePrincipalIdentifier ?? 'unknown-principal';
      const { kind, label } = describeResource(p.Resource);
      out.push({
        resourceTypeKey: 'lake_formation_permission',
        resourceId: `${ctx.region}:${principalId}:${kind}:${label}`,
        region: ctx.region,
        resourceName: `${principalId} on ${kind}:${label}`,
        metadata: {
          principal: principalId,
          resourceKind: kind,
          resource: p.Resource,
          permissions: p.Permissions ?? [],
          permissionsWithGrantOption: p.PermissionsWithGrantOption ?? [],
          resourceShare: p.AdditionalDetails?.ResourceShare ?? null,
          lastUpdated: p.LastUpdated ?? null,
          lastUpdatedBy: p.LastUpdatedBy ?? null,
        },
      });
    }
    nextToken = body.NextToken;
    page += 1;
  } while (nextToken && page < 20);

  return out;
}
