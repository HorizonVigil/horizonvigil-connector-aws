import { paginateJsonApi, detectJsonTruncation, jsonPageItems, incompleteSink } from '../pagination';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CertificateManager';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ACM_RESOURCE_TYPES = ['acm_certificate'] as const;

interface CertificateSummary {
  CertificateArn: string; DomainName?: string; Status?: string; Type?: string; NotAfter?: number; InUse?: boolean;
}

/**
 * ListCertificates, every page.
 *
 * ListCertificates is paginated on `NextToken` (page size up to 1,000). Reading
 * only the first page meant an account with more certificates than one page
 * silently reported fewer, and because finalize treats "a covering scanner did
 * not return it" as proof of deletion, the rest were soft-deleted on the next
 * scan — from a call that returned 200.
 *
 * CertificateSummary entries already include Status, so no per-certificate
 * DescribeCertificate follow-up is needed for basic inventory.
 */
export async function scanAcm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `acm.${ctx.region}.amazonaws.com`;

  const walk = await paginateJsonApi<{ CertificateSummaryList?: CertificateSummary[] }, CertificateSummary>(
    ctx.creds,
    { service: 'acm', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListCertificates`, body: {} },
    (page) => jsonPageItems<CertificateSummary>(page, 'CertificateSummaryList'),
    (page) => detectJsonTruncation(page),
    { onIncomplete: incompleteSink(ctx.creds) },
  );

  // A page that failed, or an unfinished walk, has already been reported through
  // the creds sink, which is what keeps these certificates out of tombstoning.
  // What is returned here is deliberately whatever WAS read: discarding it would
  // turn a partial shortfall into a total one.
  return walk.items
    .filter((cert) => typeof cert?.CertificateArn === 'string' && cert.CertificateArn !== '')
    .map((cert) => ({
      resourceTypeKey: 'acm_certificate',
      // The ARN is the provider-native identity. `!` was used here before; a
      // certificate summary without one cannot be identified, so it is dropped
      // rather than persisted under an undefined id.
      resourceId: cert.CertificateArn,
      region: ctx.region,
      resourceName: cert.DomainName,
      state: cert.Status,
      metadata: {
        type: cert.Type,
        notAfter: cert.NotAfter,
        inUse: cert.InUse,
        // Pages read, so a partial certificate inventory is visible in the data
        // and not only in a log line.
        acmPages: walk.pages,
        acmWalkComplete: walk.termination === 'complete',
      },
    }));
}
