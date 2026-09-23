import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, boolField } from '../xmlList';
import { describeAllQuery, keyValueMembers } from './queryMarker';
import { mapWithConcurrency } from './scannerSupport';
import { memberTexts, withoutSections } from './xmlShape';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ELB_RESOURCE_TYPES = ['elb_classic', 'elb_alb', 'elb_nlb', 'elb_gwlb', 'elb_target_group'] as const;

const V1 = '2012-06-01';
const V2 = '2015-12-01';
/** Per-load-balancer follow-ups (listeners + attributes) per region-step. */
const MAX_LB_DETAILS = 25;
const CONCURRENCY = 5;

/** Evidence from one ALB/NLB's DescribeListeners response. */
export function listenerEvidence(xml: string | null) {
  if (xml === null) return { listenersCollected: false };
  const listeners = extractListItems(extractSection(xml, 'Listeners'), 'member');
  const parsed = listeners.map((l) => {
    const actions = extractListItems(extractSection(l, 'DefaultActions'), 'member');
    const redirectsToHttps = actions.some((a) => field(a, 'Type') === 'redirect' && field(extractSection(a, 'RedirectConfig') ?? '', 'Protocol') === 'HTTPS');
    const top = withoutSections(l, ['DefaultActions', 'Certificates', 'AlpnPolicy']);
    return { protocol: field(top, 'Protocol'), port: field(top, 'Port'), sslPolicy: field(top, 'SslPolicy'), redirectsToHttps };
  });
  return {
    listenersCollected: true,
    listeners: parsed,
    // FSBP ELB.1: HTTP listeners must redirect to HTTPS.
    httpListenersWithoutRedirect: parsed.filter((l) => l.protocol === 'HTTP' && !l.redirectsToHttps).length,
    // FSBP ELB.17: TLS listeners on a recommended policy.
    sslPolicies: [...new Set(parsed.map((l) => l.sslPolicy).filter((v): v is string => !!v))],
  };
}

/** Evidence from one ALB/NLB's DescribeLoadBalancerAttributes response. */
export function v2AttributeEvidence(xml: string | null) {
  if (xml === null) return { attributesCollected: false };
  const a = keyValueMembers(xml);
  const flag = (k: string) => (k in a ? a[k] === 'true' : null);
  return {
    attributesCollected: true,
    accessLogsEnabled: flag('access_logs.s3.enabled'),              // ELB.5
    deletionProtectionEnabled: flag('deletion_protection.enabled'), // ELB.6
    dropInvalidHeaderFields: flag('routing.http.drop_invalid_header_fields.enabled'), // ELB.4
    desyncMitigationMode: a['routing.http.desync_mitigation_mode'] ?? null, // ELB.12
    wafFailOpen: flag('waf.fail_open.enabled'),
    crossZoneEnabled: flag('load_balancing.cross_zone.enabled'),
  };
}

/** Evidence for one Classic Load Balancer (listeners are inline). */
export function classicEvidence(lb: string, attrs: string | null) {
  const listeners = extractListItems(extractSection(lb, 'ListenerDescriptions'), 'member').map((d) => {
    const l = extractSection(d, 'Listener') ?? '';
    return { protocol: field(l, 'Protocol'), port: field(l, 'LoadBalancerPort'), sslCertificateId: field(l, 'SSLCertificateId') };
  });
  const top = withoutSections(lb, ['ListenerDescriptions', 'Policies', 'BackendServerDescriptions', 'Instances', 'HealthCheck', 'SourceSecurityGroup', 'SecurityGroups', 'Subnets', 'AvailabilityZones']);
  const accessLog = extractSection(attrs ?? '', 'AccessLog') ?? '';
  const draining = extractSection(attrs ?? '', 'ConnectionDraining') ?? '';
  const crossZone = extractSection(attrs ?? '', 'CrossZoneLoadBalancing') ?? '';
  return {
    dnsName: field(top, 'DNSName'), scheme: field(top, 'Scheme'), createdTime: field(top, 'CreatedTime'),
    internetFacing: field(top, 'Scheme') === 'internet-facing',
    listeners,
    // FSBP ELB.3: classic listeners should use HTTPS/SSL.
    plaintextListenerCount: listeners.filter((l) => l.protocol === 'HTTP' || l.protocol === 'TCP').length,
    attributesCollected: attrs !== null,
    accessLogsEnabled: attrs !== null ? (boolField(accessLog, 'Enabled') ?? false) : null,
    connectionDrainingEnabled: attrs !== null ? (boolField(draining, 'Enabled') ?? false) : null,
    crossZoneEnabled: attrs !== null ? (boolField(crossZone, 'Enabled') ?? false) : null,
    availabilityZones: memberTexts(lb, 'AvailabilityZones'),
  };
}

/**
 * Classic Load Balancers, ALB/NLB/GWLB and target groups (Query protocol,
 * service "elasticloadbalancing", two API versions).
 *
 * What changed, and why:
 *  - All three lists paginate (Marker → NextMarker, 400 per page). The
 *    previous version read one page, so load balancer 401 looked deleted.
 *  - Top-level fields are read with nested lists stripped (a classic LB's
 *    health check and listeners reuse element names).
 *  - Null instance ids are no longer stored in relationships.
 *  - Evidence for FSBP ELB controls, from a bounded per-LB pass: HTTP→HTTPS
 *    redirects, TLS policies, access logs, deletion protection, invalid
 *    header dropping, desync mitigation (ALB/NLB); listener protocols, access
 *    logs, connection draining and cross-zone (classic).
 */
export async function scanElb(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `elasticloadbalancing.${ctx.region}.amazonaws.com`;
  const walk = (action: string, version: string, listSection: string) => describeAllQuery(ctx, {
    service: 'elasticloadbalancing', host, version, action, listSection, itemTag: 'member',
    tokenIn: 'Marker', tokenOut: 'NextMarker', pageSizeParam: 'PageSize', pageSize: '400',
  });
  const call = async (action: string, version: string, params: Record<string, string>): Promise<string | null> => {
    const r = await callQueryApi(ctx.creds, { service: 'elasticloadbalancing', region: ctx.region, host, action, version, params });
    return r.ok ? (r.body as string) : null;
  };

  const [classic, v2, targetGroups] = await Promise.all([
    walk('DescribeLoadBalancers', V1, 'LoadBalancerDescriptions'),
    walk('DescribeLoadBalancers', V2, 'LoadBalancers'),
    walk('DescribeTargetGroups', V2, 'TargetGroups'),
  ]);

  const out: ScannedResource[] = [];

  const classicAttrs = new Map<string, string | null>();
  const classicNames = classic.items.map((lb) => field(withoutSections(lb, ['ListenerDescriptions', 'Policies']), 'LoadBalancerName')).filter((n): n is string => !!n);
  await mapWithConcurrency(classicNames.slice(0, MAX_LB_DETAILS), CONCURRENCY, async (name) => {
    classicAttrs.set(name, await call('DescribeLoadBalancerAttributes', V1, { LoadBalancerName: name }));
  });

  for (const lb of classic.items) {
    const top = withoutSections(lb, ['ListenerDescriptions', 'Policies', 'BackendServerDescriptions', 'Instances', 'HealthCheck', 'SourceSecurityGroup']);
    const name = field(top, 'LoadBalancerName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'elb_classic', resourceId: name, region: ctx.region, resourceName: name,
      metadata: classicEvidence(lb, classicAttrs.get(name) ?? null),
      relationships: {
        vpcId: field(top, 'VPCId'),
        instanceIds: extractListItems(extractSection(lb, 'Instances'), 'member').map((i) => field(i, 'InstanceId')).filter((v): v is string => !!v),
        securityGroupIds: memberTexts(lb, 'SecurityGroups'),
        subnetIds: memberTexts(lb, 'Subnets'),
      },
    });
  }

  const v2Arns = v2.items.map((lb) => field(lb, 'LoadBalancerArn')).filter((a): a is string => !!a);
  const v2Details = new Map<string, { listeners: string | null; attributes: string | null }>();
  await mapWithConcurrency(v2Arns.slice(0, MAX_LB_DETAILS), CONCURRENCY, async (arn) => {
    const [listeners, attributes] = await Promise.all([
      call('DescribeListeners', V2, { LoadBalancerArn: arn, PageSize: '400' }),
      call('DescribeLoadBalancerAttributes', V2, { LoadBalancerArn: arn }),
    ]);
    v2Details.set(arn, { listeners, attributes });
  });

  for (const lb of v2.items) {
    const top = withoutSections(lb, ['AvailabilityZones', 'SecurityGroups', 'State']);
    const arn = field(top, 'LoadBalancerArn');
    if (!arn) continue;
    const type = field(top, 'Type'); // 'application' | 'network' | 'gateway'
    const resourceTypeKey = type === 'network' ? 'elb_nlb' : type === 'gateway' ? 'elb_gwlb' : type === 'application' ? 'elb_alb' : null;
    if (!resourceTypeKey) continue; // an unrecognized future type
    const stateSection = extractSection(lb, 'State');
    const d = v2Details.get(arn);
    out.push({
      resourceTypeKey, resourceId: arn, region: ctx.region, resourceName: field(top, 'LoadBalancerName') ?? undefined,
      state: stateSection ? (field(stateSection, 'Code') ?? undefined) : undefined,
      metadata: {
        dnsName: field(top, 'DNSName'), scheme: field(top, 'Scheme'), createdTime: field(top, 'CreatedTime'),
        internetFacing: field(top, 'Scheme') === 'internet-facing',
        ipAddressType: field(top, 'IpAddressType'),
        availabilityZoneCount: extractListItems(extractSection(lb, 'AvailabilityZones'), 'member').length,
        ...listenerEvidence(d ? d.listeners : null),
        ...v2AttributeEvidence(d ? d.attributes : null),
      },
      relationships: {
        vpcId: field(top, 'VpcId'),
        securityGroupIds: memberTexts(lb, 'SecurityGroups'),
        subnetIds: extractListItems(extractSection(lb, 'AvailabilityZones'), 'member').map((z) => field(z, 'SubnetId')).filter((v): v is string => !!v),
      },
    });
  }

  for (const tg of targetGroups.items) {
    const top = withoutSections(tg, ['LoadBalancerArns', 'Matcher']);
    const arn = field(top, 'TargetGroupArn');
    const name = field(top, 'TargetGroupName');
    if (!arn || !name) continue;
    out.push({
      resourceTypeKey: 'elb_target_group', resourceId: arn, region: ctx.region, resourceName: name,
      metadata: {
        protocol: field(top, 'Protocol'), port: field(top, 'Port'), targetType: field(top, 'TargetType'),
        healthCheckProtocol: field(top, 'HealthCheckProtocol'),
        healthCheckEnabled: boolField(top, 'HealthCheckEnabled') ?? null,
        healthCheckPath: field(top, 'HealthCheckPath'),
      },
      relationships: {
        vpcId: field(top, 'VpcId'),
        loadBalancerArns: memberTexts(tg, 'LoadBalancerArns'),
      },
    });
  }

  return out;
}
