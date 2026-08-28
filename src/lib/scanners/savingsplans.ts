import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const HOST = 'savingsplans.amazonaws.com';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SAVINGSPLANS_RESOURCE_TYPES = ['savings_plan'] as const;

interface SavingsPlan {
  savingsPlanId?: string;
  savingsPlanArn?: string;
  savingsPlanType?: string;
  state?: string;
  region?: string;
  ec2InstanceFamily?: string;
  offeringId?: string;
  productTypes?: string[];
  paymentOption?: string;
  commitment?: string;
  upfrontPaymentAmount?: string;
  recurringPaymentAmount?: string;
  termDurationInSeconds?: number;
  currency?: string;
  start?: string;
  end?: string;
  description?: string;
  returnableUntil?: string;
  tags?: Record<string, string>;
}
interface DescribeSavingsPlansResponse { savingsPlans?: SavingsPlan[]; nextToken?: string }

/**
 * AWS Savings Plans (the billing *commitment* inventory itself -- distinct
 * from the coverage/utilization/recommendation data already surfaced via
 * ce.ts) -- account-wide and, like Cost Explorer/Budgets, effectively a
 * single global endpoint. Intended for GLOBAL_SCANNERS in discovery.ts, not
 * REGIONAL_SCANNERS -- that wiring is out of scope for this file (someone
 * else is doing one consolidated pass to register every new scanner).
 *
 * Below is exactly which parts were CONFIRMED via search vs. BEST-GUESSED
 * from AWS convention, per the extra uncertainty called out for this one:
 *
 * - Protocol -- CONFIRMED, not guessed. Fetched the service's actual
 *   botocore service model (savingsplans/2019-06-28/service-2.json); its
 *   metadata block reads `"protocol": "rest-json"` with no `targetPrefix`,
 *   i.e. NOT the JSON-RPC 1.1 (X-Amz-Target / application/x-amz-json-1.1)
 *   style callJsonApi/athena.ts/ce.ts/budgets.ts use. Independently
 *   corroborated by AWS's own DescribeSavingsPlans API reference page,
 *   whose "Request Syntax" is a literal `POST /DescribeSavingsPlans
 *   HTTP/1.1` with `Content-type: application/json` and a plain JSON body
 *   -- no target header. That's why this file uses createAwsClient +
 *   safeFetch with an explicit path, the same shape as inspector2.ts,
 *   instead of callJsonApi.
 *
 * - Operation name and request/response shape -- CONFIRMED via the same AWS
 *   API reference page (docs.aws.amazon.com/savingsplans/latest/APIReference
 *   /API_DescribeSavingsPlans.html): operation is `DescribeSavingsPlans`,
 *   paginated via `maxResults`/`nextToken`, returning
 *   `savingsPlans: SavingsPlan[]`. The SavingsPlan interface below is a
 *   direct transcription of that page's documented Response Syntax
 *   (savingsPlanId, savingsPlanArn, savingsPlanType, state, region,
 *   ec2InstanceFamily, commitment, termDurationInSeconds, etc.), not a
 *   guess.
 *
 * - Global vs. regional -- CONFIRMED via search, not just defaulted. AWS's
 *   own General Reference "AWS Billing and Cost Management endpoints and
 *   quotas" page lists a Savings Plans service-endpoints table where every
 *   single region row (us-east-1, eu-west-1, ap-southeast-2, GovCloud,
 *   etc.) resolves to the SAME bare hostname `savingsplans.amazonaws.com`
 *   -- no region-suffixed hostname exists for this service anywhere in that
 *   table. That's the identical pattern budgets.ts already relies on for
 *   `budgets.amazonaws.com` (also listed once, reused across every region
 *   row). Host and global treatment below follow directly from that.
 *
 * - Signing region param -- BEST-GUESS by AWS convention, not separately
 *   confirmed: SigV4 still requires *some* region for the credential scope
 *   even though the host itself has no region suffix, so this follows
 *   budgets.ts/ce.ts's own choice of 'us-east-1' for that parameter;
 *   ctx.region is deliberately ignored, same as those two.
 *
 * UNVERIFIED against a real account's actual Savings Plans response shape
 * until this runs against a live connection and gets checked -- same
 * disclosed-uncertainty convention as inspectorFindings.ts/inspector2.ts.
 * An account with no Savings Plans ever purchased is the expected, honest
 * empty case, not an error.
 */
export async function scanSavingsPlans(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'savingsplans', 'us-east-1');
  const out: ScannedResource[] = [];
  let nextToken: string | undefined;

  do {
    const res = await safeFetch(client, `https://${HOST}/DescribeSavingsPlans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxResults: 100, ...(nextToken ? { nextToken } : {}) }),
    });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Savings Plans DescribeSavingsPlans failed (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      break;
    }

    const body = text ? (JSON.parse(text) as DescribeSavingsPlansResponse) : {};
    for (const sp of body.savingsPlans ?? []) {
      const resourceId = sp.savingsPlanArn ?? sp.savingsPlanId;
      if (!resourceId) continue;
      out.push({
        resourceTypeKey: 'savings_plan', resourceId, region: null,
        resourceName: sp.description || sp.savingsPlanId || sp.savingsPlanArn,
        state: sp.state,
        tags: sp.tags,
        metadata: {
          savingsPlanType: sp.savingsPlanType,
          planRegion: sp.region ?? null,
          ec2InstanceFamily: sp.ec2InstanceFamily ?? null,
          offeringId: sp.offeringId,
          productTypes: sp.productTypes,
          paymentOption: sp.paymentOption,
          commitment: sp.commitment,
          currency: sp.currency,
          upfrontPaymentAmount: sp.upfrontPaymentAmount,
          recurringPaymentAmount: sp.recurringPaymentAmount,
          termDurationInSeconds: sp.termDurationInSeconds,
          start: sp.start,
          end: sp.end,
          returnableUntil: sp.returnableUntil,
        },
      });
    }
    nextToken = body.nextToken;
  } while (nextToken);

  return out;
}
