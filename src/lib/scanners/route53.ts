import { createAwsClient, safeFetch } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ROUTE53_RESOURCE_TYPES = ['route53_hosted_zone', 'route53_health_check', 'route53_record'] as const;

/**
 * Route53 is REST-XML, global (one endpoint, no per-region data) — a
 * GLOBAL_SCANNERS entry like IAM/S3, signed against us-east-1 regardless
 * of ctx.region. Unlike S3's ListBuckets, the response here has one
 * wrapper element (ListHostedZonesResponse) directly around the list, not
 * the "...Result" nesting Query-protocol services use.
 */
export async function scanRoute53(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'route53', 'us-east-1');
  const get = async (path: string): Promise<string> => {
    const res = await safeFetch(client, `https://route53.amazonaws.com${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Route53 GET ${path} failed (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return '';
    }
    return text;
  };

  const out: ScannedResource[] = [];

  const zonesXml = await get('/2013-04-01/hostedzone');
  const zoneItems = extractListItems(extractSection(zonesXml, 'HostedZones'), 'HostedZone');
  for (const zone of zoneItems) {
    const id = field(zone, 'Id'); // "/hostedzone/Z1234567890"
    if (!id) continue;
    const config = extractSection(zone, 'Config');
    out.push({
      resourceTypeKey: 'route53_hosted_zone', resourceId: id.replace('/hostedzone/', ''), region: null,
      resourceName: field(zone, 'Name') ?? undefined,
      metadata: {
        recordSetCount: numField(zone, 'ResourceRecordSetCount'),
        privateZone: config ? boolField(config, 'PrivateZone') : false,
        comment: config ? field(config, 'Comment') : null,
      },
    });
  }

  const healthChecksXml = await get('/2013-04-01/healthcheck');
  for (const hc of extractListItems(extractSection(healthChecksXml, 'HealthChecks'), 'HealthCheck')) {
    const id = field(hc, 'Id');
    if (!id) continue;
    const config = extractSection(hc, 'HealthCheckConfig');
    out.push({
      resourceTypeKey: 'route53_health_check', resourceId: id, region: null,
      metadata: {
        type: config ? field(config, 'Type') : null, fqdn: config ? field(config, 'FullyQualifiedDomainName') : null,
        port: config ? numField(config, 'Port') : undefined,
      },
    });
  }

  // Record sets are listed per-zone, not account-wide — capped to the first
  // 10 zones and 100 records each to stay well inside Cloudflare's
  // free-tier ~50-subrequest budget for one invocation.
  for (const zone of zoneItems.slice(0, 10)) {
    const id = field(zone, 'Id');
    if (!id) continue;
    const zoneId = id.replace('/hostedzone/', '');
    const recordsXml = await get(`/2013-04-01/hostedzone/${zoneId}/rrset?maxitems=100`);
    for (const rr of extractListItems(extractSection(recordsXml, 'ResourceRecordSets'), 'ResourceRecordSet')) {
      const name = field(rr, 'Name');
      const type = field(rr, 'Type');
      if (!name || !type) continue;
      out.push({
        resourceTypeKey: 'route53_record', resourceId: `${zoneId}:${name}:${type}`, region: null, resourceName: `${name} (${type})`,
        metadata: { ttl: numField(rr, 'TTL'), setIdentifier: field(rr, 'SetIdentifier') },
        relationships: { hostedZoneId: zoneId },
      });
    }
  }

  return out;
}
