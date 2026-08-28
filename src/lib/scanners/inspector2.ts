import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const INSPECTOR2_RESOURCE_TYPES = ['inspector_account_status'] as const;

interface ResourceStateStatus { status?: string; errorCode?: string; errorMessage?: string }
interface AccountResourceState {
  ec2?: { status?: ResourceStateStatus }; ecr?: { status?: ResourceStateStatus };
  lambda?: { status?: ResourceStateStatus }; lambdaCode?: { status?: ResourceStateStatus };
}
interface AccountStatus { accountId: string; state?: { status?: string; errorCode?: string; errorMessage?: string }; resourceState?: AccountResourceState }
interface BatchGetAccountStatusResponse { accounts?: AccountStatus[] }

/**
 * Amazon Inspector v2 account-level enablement/coverage status -- a
 * resource-inventory counterpart to inspectorFindings.ts's own findings
 * scan, same REST-JSON (POST /status/batch/get) request family. Regional,
 * not global -- Inspector is enabled per region like GuardDuty/Security Hub
 * (see discovery.ts's REGIONAL_SCANNERS, where those two already live),
 * registered there rather than in GLOBAL_SCANNERS.
 *
 * UNVERIFIED against a real AWS account with Inspector enabled -- same
 * disclosed uncertainty as inspectorFindings.ts (no test account had it
 * active when either file was written). An AccessDeniedException-style
 * failure here is the expected, honest "not enrolled" case, logged and
 * skipped rather than thrown, same as every other optional-service scanner
 * in this connector.
 */
export async function scanInspector2(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'inspector2', ctx.region);
  const base = `https://inspector2.${ctx.region}.amazonaws.com`;

  const res = await safeFetch(client, `${base}/status/batch/get`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Inspector2 BatchGetAccountStatus failed in ${ctx.region} (continuing without it — likely just not enabled there): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const body = text ? (JSON.parse(text) as BatchGetAccountStatusResponse) : {};
  const out: ScannedResource[] = [];
  for (const acct of body.accounts ?? []) {
    out.push({
      resourceTypeKey: 'inspector_account_status', resourceId: `${acct.accountId}:${ctx.region}`, region: ctx.region,
      resourceName: `Inspector — ${acct.accountId}`,
      state: acct.state?.status,
      metadata: {
        stateError: acct.state?.errorCode ?? null,
        ec2Status: acct.resourceState?.ec2?.status?.status ?? null,
        ecrStatus: acct.resourceState?.ecr?.status?.status ?? null,
        lambdaStatus: acct.resourceState?.lambda?.status?.status ?? null,
        lambdaCodeStatus: acct.resourceState?.lambdaCode?.status?.status ?? null,
      },
    });
  }
  return out;
}
