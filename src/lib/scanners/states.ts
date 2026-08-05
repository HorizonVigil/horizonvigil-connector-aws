import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSStepFunctions';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const STATES_RESOURCE_TYPES = ['step_functions_state_machine', 'step_functions_activity'] as const;

interface StateMachine {
  stateMachineArn: string; name: string; type?: string; creationDate?: number;
}
interface Activity {
  activityArn: string; name: string; creationDate?: number;
}

/** Step Functions is JSON-RPC (service "states", target prefix AWSStepFunctions) — two independent account/region-wide list calls, no per-item fan-out needed. */
export async function scanStates(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `states.${ctx.region}.amazonaws.com`;
  const call = async (action: string) => {
    const result = await callJsonApi(ctx.creds, { service: 'states', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body: {} });
    if (!result.ok) {
      console.error(`Step Functions ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const machinesBody = await call('ListStateMachines');
  for (const m of (machinesBody?.stateMachines as StateMachine[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'step_functions_state_machine', resourceId: m.stateMachineArn, region: ctx.region, resourceName: m.name,
      metadata: { type: m.type, createdAt: m.creationDate },
    });
  }

  const activitiesBody = await call('ListActivities');
  for (const a of (activitiesBody?.activities as Activity[] | undefined) ?? []) {
    out.push({ resourceTypeKey: 'step_functions_activity', resourceId: a.activityArn, region: ctx.region, resourceName: a.name, metadata: { createdAt: a.creationDate } });
  }

  return out;
}
