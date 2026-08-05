import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSEvents';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EVENTS_RESOURCE_TYPES = ['eventbridge_bus', 'eventbridge_rule'] as const;

interface EventBus {
  Name: string; Arn?: string; Policy?: string;
}
interface Rule {
  Name: string; Arn?: string; State?: string; Description?: string; ScheduleExpression?: string; EventPattern?: string;
}

/**
 * EventBridge is JSON-RPC (service "events", target prefix AWSEvents),
 * same signer pattern as DynamoDB/ECS. Rules are listed per event bus —
 * the account always has at least the built-in "default" bus, plus any
 * custom ones, so this lists buses first, then rules for each (capped,
 * same free-tier-subrequest-budget reasoning as every fan-out in this file).
 */
export async function scanEvents(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `events.${ctx.region}.amazonaws.com`;
  const call = async (action: string, body: Record<string, unknown> = {}) => {
    const result = await callJsonApi(ctx.creds, { service: 'events', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body });
    if (!result.ok) {
      console.error(`EventBridge ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const busesBody = await call('ListEventBuses');
  const buses = (busesBody?.EventBuses as EventBus[] | undefined) ?? [];
  for (const b of buses) {
    out.push({ resourceTypeKey: 'eventbridge_bus', resourceId: b.Arn ?? b.Name, region: ctx.region, resourceName: b.Name });
  }

  for (const bus of buses.slice(0, 10)) {
    const rulesBody = await call('ListRules', { EventBusName: bus.Name, Limit: 50 });
    for (const r of (rulesBody?.Rules as Rule[] | undefined) ?? []) {
      out.push({
        resourceTypeKey: 'eventbridge_rule', resourceId: r.Arn ?? `${bus.Name}/${r.Name}`, region: ctx.region, resourceName: r.Name,
        state: r.State, metadata: { description: r.Description, scheduleExpression: r.ScheduleExpression },
        relationships: { eventBusName: bus.Name },
      });
    }
  }

  return out;
}
