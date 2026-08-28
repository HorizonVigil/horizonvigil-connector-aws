import { callJsonApi, callQueryApi } from '../awsApi';
import { field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSBudgetServiceGateway';
const HOST = 'budgets.amazonaws.com';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const BUDGETS_RESOURCE_TYPES = ['budgets_budget'] as const;

interface BudgetAmount { Amount?: string; Unit?: string }
interface Budget {
  BudgetName: string; BudgetType?: string; TimeUnit?: string;
  BudgetLimit?: BudgetAmount; CalculatedSpend?: { ActualSpend?: BudgetAmount; ForecastedSpend?: BudgetAmount };
  LastUpdatedTime?: number;
}

/**
 * AWS Budgets is account-wide and global (no region concept at all) --
 * registered as a GLOBAL_SCANNERS entry in discovery.ts, same as
 * ce.ts/iam.ts. DescribeBudgets requires the caller's own AWS account id
 * (AccountId) as an explicit body param -- resolved via STS
 * GetCallerIdentity, same account-ID-via-STS pattern s3control.ts already
 * uses, rather than widening ScannerContext (which would touch every one
 * of the other 96 scanners' call sites for a need only these two have).
 *
 * UNVERIFIED against a real account's actual Budgets response shape until
 * this runs against a live connection and gets checked -- same disclosed-
 * uncertainty convention as inspectorFindings.ts.
 */
export async function scanBudgets(ctx: ScannerContext): Promise<ScannedResource[]> {
  const out: ScannedResource[] = [];

  const stsResult = await callQueryApi(ctx.creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
  const accountId = stsResult.ok ? field(stsResult.body as string, 'Account') : null;
  if (!accountId) {
    console.error('Budgets scan skipped: could not resolve account ID via STS GetCallerIdentity.');
    return out;
  }

  let nextToken: string | undefined;

  do {
    const res = await callJsonApi(ctx.creds, {
      service: 'budgets', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.DescribeBudgets`,
      body: { AccountId: accountId, MaxResults: 100, ...(nextToken ? { NextToken: nextToken } : {}) },
    });
    if (!res.ok) {
      console.error(`Budgets DescribeBudgets failed (continuing without it): ${res.errorMessage ?? res.errorCode ?? res.status}`);
      break;
    }
    const body = res.body as { Budgets?: Budget[]; NextToken?: string };
    for (const b of body.Budgets ?? []) {
      out.push({
        resourceTypeKey: 'budgets_budget', resourceId: `${accountId}:${b.BudgetName}`, region: null, resourceName: b.BudgetName,
        metadata: {
          budgetType: b.BudgetType, timeUnit: b.TimeUnit,
          limit: b.BudgetLimit ? `${b.BudgetLimit.Amount} ${b.BudgetLimit.Unit}` : null,
          actualSpend: b.CalculatedSpend?.ActualSpend ? `${b.CalculatedSpend.ActualSpend.Amount} ${b.CalculatedSpend.ActualSpend.Unit}` : null,
          forecastedSpend: b.CalculatedSpend?.ForecastedSpend ? `${b.CalculatedSpend.ForecastedSpend.Amount} ${b.CalculatedSpend.ForecastedSpend.Unit}` : null,
          lastUpdatedTime: b.LastUpdatedTime,
        },
      });
    }
    nextToken = body.NextToken;
  } while (nextToken);

  return out;
}
