import { callJsonApi } from '../awsApi';
import { accountIdFromArn, summarizePolicy } from './policyEvidence';
import { reportWalk, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSEvents';
/** ListTargetsByRule follow-ups per region-step. */
const MAX_TARGET_LOOKUPS = 40;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EVENTS_RESOURCE_TYPES = ['eventbridge_bus', 'eventbridge_rule'] as const;

interface EventBus { Name: string; Arn?: string; Policy?: string; KmsKeyIdentifier?: string; Description?: string }
interface Rule {
  Name: string; Arn?: string; State?: string; Description?: string; ScheduleExpression?: string; EventPattern?: string;
  ManagedBy?: string; RoleArn?: string; EventBusName?: string;
}
interface Target { Id?: string; Arn?: string; RoleArn?: string }

/**
 * EventBridge buses and rules (JSON-RPC, AWSEvents).
 *
 * What changed, and why:
 *  - Buses paginate, and rules paginate PER BUS. The previous version read 10
 *    buses and 50 rules each, silently: rule 51 looked deleted.
 *  - Failures are reported rather than logged and dropped.
 *  - Evidence: each bus's resource policy (who may put events -- anonymous or
 *    other accounts) and KMS key; each rule's targets (bounded), including
 *    targets in other accounts, which is how events leave the account.
 */
export async function scanEvents(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `events.${ctx.region}.amazonaws.com`;

  const busesWalk = await walkJsonRpc<EventBus>(ctx, { service: 'events', host, target: `${TARGET_PREFIX}.ListEventBuses`, body: { Limit: 100 } }, 'EventBuses');
  reportWalk(ctx, busesWalk, 'events', 'ListEventBuses');
  const buses = busesWalk.items.filter((b) => !!b?.Name);

  const rulesPerBus = await mapWithConcurrency(buses, 4, async (bus) => {
    const w = await walkJsonRpc<Rule>(ctx, { service: 'events', host, target: `${TARGET_PREFIX}.ListRules`, body: { EventBusName: bus.Name, Limit: 100 } }, 'Rules');
    reportWalk(ctx, w, 'events', 'ListRules');
    return { bus, rules: w.items.filter((r) => !!r?.Name) };
  });

  const allRules = rulesPerBus.flatMap(({ bus, rules }) => rules.map((r) => ({ bus, r })));
  const targets = new Map<string, Target[] | null>();
  await mapWithConcurrency(allRules.filter(({ r }) => !r.ManagedBy).slice(0, MAX_TARGET_LOOKUPS), 4, async ({ bus, r }) => {
    const res = await callJsonApi(ctx.creds, { service: 'events', region: ctx.region, host, target: `${TARGET_PREFIX}.ListTargetsByRule`, body: { Rule: r.Name, EventBusName: bus.Name, Limit: 100 } });
    targets.set(`${bus.Name}/${r.Name}`, res.ok ? ((res.body as { Targets?: Target[] } | null)?.Targets ?? []) : null);
  });

  const out: ScannedResource[] = [];
  for (const b of buses) {
    const own = accountIdFromArn(b.Arn);
    out.push({
      resourceTypeKey: 'eventbridge_bus', resourceId: b.Arn ?? b.Name, region: ctx.region, resourceName: b.Name,
      metadata: {
        isDefault: b.Name === 'default',
        kmsKeyIdentifier: b.KmsKeyIdentifier ?? null,
        resourcePolicy: summarizePolicy(b.Policy, own),
      },
    });
  }
  for (const { bus, r } of allRules) {
    const own = accountIdFromArn(r.Arn ?? bus.Arn);
    const t = targets.get(`${bus.Name}/${r.Name}`);
    const targetArns = (t ?? []).map((x) => x.Arn).filter((v): v is string => !!v);
    out.push({
      resourceTypeKey: 'eventbridge_rule', resourceId: r.Arn ?? `${bus.Name}/${r.Name}`, region: ctx.region, resourceName: r.Name,
      state: r.State,
      metadata: {
        description: r.Description, scheduleExpression: r.ScheduleExpression,
        managedBy: r.ManagedBy ?? null,
        targetsCollected: t !== undefined && t !== null,
        targetCount: t ? t.length : null,
        crossAccountTargetArns: targetArns.filter((a) => { const acct = accountIdFromArn(a); return !!acct && !!own && acct !== own; }),
      },
      relationships: { eventBusName: bus.Name, roleArn: r.RoleArn ?? null, targetArns },
    });
  }
  return out;
}
