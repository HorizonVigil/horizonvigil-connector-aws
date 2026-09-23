import { callQueryApi } from '../awsApi';
import { field } from '../xmlList';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { reportListingFailure } from './scannerSupport';
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
  TimePeriod?: { Start?: number; End?: number };
}

const amountText = (a: BudgetAmount | undefined) => (a ? `${a.Amount} ${a.Unit}` : null);
const amountNumber = (a: BudgetAmount | undefined): number | null => {
  const n = a?.Amount === undefined ? NaN : Number(a.Amount);
  return Number.isFinite(n) ? n : null;
};

/** Evidence for one budget. The *Text keys keep the previous string format. */
export function budgetMetadata(b: Budget) {
  const limit = amountNumber(b.BudgetLimit);
  const forecast = amountNumber(b.CalculatedSpend?.ForecastedSpend);
  return {
    budgetType: b.BudgetType, timeUnit: b.TimeUnit,
    limit: amountText(b.BudgetLimit),
    actualSpend: amountText(b.CalculatedSpend?.ActualSpend),
    forecastedSpend: amountText(b.CalculatedSpend?.ForecastedSpend),
    limitAmount: limit,
    actualSpendAmount: amountNumber(b.CalculatedSpend?.ActualSpend),
    forecastedSpendAmount: forecast,
    currency: b.BudgetLimit?.Unit ?? null,
    forecastExceedsLimit: limit !== null && forecast !== null ? forecast > limit : null,
    lastUpdatedTime: b.LastUpdatedTime,
    lastUpdatedIso: toIso(b.LastUpdatedTime),
  };
}

/**
 * AWS Budgets — account-wide and global (a GLOBAL_SCANNERS entry, like
 * ce.ts/iam.ts). DescribeBudgets needs the account id, resolved via STS
 * GetCallerIdentity (same pattern as s3control.ts).
 *
 * What changed: an unresolved account id, or a failed/partial
 * DescribeBudgets walk, is now REPORTED rather than returning [] or a short
 * list -- both of which finalize read as "budgets deleted". Amounts are also
 * kept as numbers (the old strings are unchanged) so posture can compare
 * forecast against limit.
 *
 * Note: CalculatedSpend changes as money is spent, so budget rows change on
 * most scans by nature; that is the data, not churn to suppress.
 */
export async function scanBudgets(ctx: ScannerContext): Promise<ScannedResource[]> {
  const stsResult = await callQueryApi(ctx.creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
  const accountId = stsResult.ok ? field(stsResult.body as string, 'Account') : null;
  if (!accountId) {
    console.error('Budgets scan skipped: could not resolve account ID via STS GetCallerIdentity.');
    reportListingFailure(ctx, { service: 'budgets', action: 'DescribeBudgets', region: 'us-east-1' });
    return [];
  }

  const walk = await walkJsonRpc<Budget>(ctx, {
    service: 'budgets', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.DescribeBudgets`,
    body: { AccountId: accountId, MaxResults: 100 },
  }, 'Budgets');
  reportWalk(ctx, walk, 'budgets', 'DescribeBudgets', 'us-east-1');

  const out: ScannedResource[] = [];
  const seen = new Set<string>();
  for (const b of walk.items) {
    if (!b?.BudgetName) continue;
    const id = `${accountId}:${b.BudgetName}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      resourceTypeKey: 'budgets_budget', resourceId: id, region: null, resourceName: b.BudgetName,
      metadata: budgetMetadata(b),
    });
  }
  return out;
}