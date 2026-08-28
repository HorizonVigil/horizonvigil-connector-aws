import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const MQ_RESOURCE_TYPES = ['mq_broker'] as const;

type BrokerState =
  | 'CREATION_IN_PROGRESS' | 'CREATION_FAILED' | 'DELETION_IN_PROGRESS'
  | 'RUNNING' | 'REBOOT_IN_PROGRESS' | 'CRITICAL_ACTION_REQUIRED' | 'REPLICA';
type EngineType = 'ACTIVEMQ' | 'RABBITMQ';
type DeploymentMode = 'SINGLE_INSTANCE' | 'ACTIVE_STANDBY_MULTI_AZ' | 'CLUSTER_MULTI_AZ';

interface BrokerSummary {
  brokerArn?: string;
  brokerId?: string;
  brokerName?: string;
  brokerState?: BrokerState;
  engineType?: EngineType;
  deploymentMode?: DeploymentMode;
  hostInstanceType?: string;
  created?: string;
}
interface ListBrokersResponse { brokerSummaries?: BrokerSummary[]; nextToken?: string }

/**
 * Amazon MQ (managed ActiveMQ/RabbitMQ brokers) — REST-JSON, confirmed via
 * AWS's own Amazon MQ REST API reference (brokers.html): GET /v1/brokers
 * lists every broker in the region as flat summaries (brokerArn, brokerId,
 * brokerName, brokerState, engineType, deploymentMode, hostInstanceType,
 * created) — no separate DescribeBroker call is needed to get these fields,
 * unlike es.ts's list-then-describe pattern. Regional host
 * (mq.<region>.amazonaws.com), same createAwsClient + safeFetch pattern as
 * inspector2.ts/es.ts.
 *
 * The response supports nextToken/maxResults pagination, but only the first
 * page (default maxResults=20) is fetched here — acceptable for a first
 * pass per the same reasoning as other list-only scanners in this
 * connector; a follow-up pass can add the nextToken loop if accounts with
 * >20 brokers turn out to be common.
 *
 * UNVERIFIED against a real account's actual response shape until this runs
 * against a live connection and gets checked -- same disclosed-uncertainty
 * convention as inspector2.ts/es.ts.
 */
export async function scanMq(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'mq', ctx.region);
  const base = `https://mq.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const res = await safeFetch(client, `${base}/v1/brokers`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Amazon MQ ListBrokers failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return out;
  }

  const brokers = (text ? (JSON.parse(text) as ListBrokersResponse) : {}).brokerSummaries ?? [];
  for (const b of brokers) {
    out.push({
      resourceTypeKey: 'mq_broker',
      resourceId: b.brokerArn ?? b.brokerId ?? `${ctx.region}:unknown`,
      region: ctx.region,
      resourceName: b.brokerName,
      state: b.brokerState,
      metadata: {
        brokerId: b.brokerId,
        engineType: b.engineType,
        deploymentMode: b.deploymentMode,
        hostInstanceType: b.hostInstanceType,
        created: b.created,
      },
    });
  }

  return out;
}
