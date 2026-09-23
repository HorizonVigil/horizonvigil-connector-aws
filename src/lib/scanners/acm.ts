import { paginateJsonApi, detectJsonTruncation, jsonPageItems, incompleteSink } from '../pagination';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CertificateManager';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ACM_RESOURCE_TYPES = ['acm_certificate'] as const;

/**
 * Every key algorithm ACM supports.
 *
 * ListCertificates' DEFAULT filter returns only RSA_1024 and RSA_2048
 * certificates. Without this, every ECDSA (EC_prime256v1 / EC_secp384r1 /
 * EC_secp521r1) and RSA_3072 / RSA_4096 certificate was invisible -- never
 * inventoried, never checked for expiry -- from a call that returned 200.
 */
export const ALL_KEY_TYPES = [
  'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096', 'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1',
] as const;

interface CertificateSummary {
  CertificateArn: string;
  DomainName?: string;
  Status?: string;
  Type?: string;
  KeyAlgorithm?: string;
  KeyUsages?: string[];
  ExtendedKeyUsages?: string[];
  RenewalEligibility?: string;
  InUse?: boolean;
  Exported?: boolean;
  ExportOption?: string;
  ManagedBy?: string;
  HasAdditionalSubjectAlternativeNames?: boolean;
  SubjectAlternativeNameSummaries?: string[];
  NotBefore?: number | string;
  NotAfter?: number | string;
  CreatedAt?: number | string;
  IssuedAt?: number | string;
  ImportedAt?: number | string;
  RevokedAt?: number | string;
}

/** ACM's JSON protocol returns timestamps as epoch SECONDS. */
export function toIsoTimestamp(value: number | string | undefined | null): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number') return Number.isFinite(value) ? new Date(value * 1000).toISOString() : null;
  return value;
}

/**
 * Metadata for one certificate.
 *
 * Deliberately NO "days until expiry": that value changes every day, which
 * would make every certificate look modified on every scan. Posture computes
 * it from `notAfterIso` at evaluation time.
 *
 * `notAfter` keeps its original raw form (epoch seconds) for existing
 * consumers; `notAfterIso` is the normalized value new consumers should use.
 */
export function certificateMetadata(cert: CertificateSummary) {
  return {
    type: cert.Type,
    notAfter: cert.NotAfter,
    notAfterIso: toIsoTimestamp(cert.NotAfter),
    notBeforeIso: toIsoTimestamp(cert.NotBefore),
    inUse: cert.InUse,
    keyAlgorithm: cert.KeyAlgorithm ?? null,
    renewalEligibility: cert.RenewalEligibility ?? null,
    exported: cert.Exported ?? null,
    exportOption: cert.ExportOption ?? null,
    managedBy: cert.ManagedBy ?? null,
    keyUsages: cert.KeyUsages ?? [],
    extendedKeyUsages: cert.ExtendedKeyUsages ?? [],
    subjectAlternativeNames: cert.SubjectAlternativeNameSummaries ?? [],
    hasAdditionalSubjectAlternativeNames: cert.HasAdditionalSubjectAlternativeNames ?? false,
    // A wildcard certificate widens blast radius if its key leaks.
    isWildcard: [cert.DomainName, ...(cert.SubjectAlternativeNameSummaries ?? [])].some((d) => typeof d === 'string' && d.startsWith('*.')),
    createdAtIso: toIsoTimestamp(cert.CreatedAt),
    issuedAtIso: toIsoTimestamp(cert.IssuedAt),
    importedAtIso: toIsoTimestamp(cert.ImportedAt),
    revokedAtIso: toIsoTimestamp(cert.RevokedAt),
  };
}

/**
 * ListCertificates, every page, every key algorithm, every status.
 *
 * Paginated on `NextToken` (page size up to 1,000). A page that failed, or an
 * unfinished walk, is reported through the creds sink, which is what keeps
 * these certificates out of tombstoning. What is returned is deliberately
 * whatever WAS read: discarding it would turn a partial shortfall into a
 * total one.
 *
 * CertificateSummary already carries status, dates, key algorithm, renewal
 * eligibility and in-use, so no per-certificate DescribeCertificate is needed.
 */
export async function scanAcm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `acm.${ctx.region}.amazonaws.com`;

  const walk = await paginateJsonApi<{ CertificateSummaryList?: CertificateSummary[] }, CertificateSummary>(
    ctx.creds,
    {
      service: 'acm', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListCertificates`,
      body: { Includes: { keyTypes: [...ALL_KEY_TYPES] }, MaxItems: 1000 },
    },
    (page) => jsonPageItems<CertificateSummary>(page, 'CertificateSummaryList'),
    (page) => detectJsonTruncation(page),
    { onIncomplete: incompleteSink(ctx.creds) },
  );

  if (walk.termination !== 'complete') {
    console.error(`ACM ListCertificates in ${ctx.region} ended '${walk.termination}' after ${walk.pages} page(s); returning what was read.`);
  }

  const seen = new Set<string>();
  const out: ScannedResource[] = [];
  for (const cert of walk.items) {
    // A summary without an ARN cannot be identified; dropped rather than
    // persisted under an undefined id.
    if (typeof cert?.CertificateArn !== 'string' || cert.CertificateArn === '') continue;
    if (seen.has(cert.CertificateArn)) continue;
    seen.add(cert.CertificateArn);
    out.push({
      resourceTypeKey: 'acm_certificate',
      resourceId: cert.CertificateArn,
      region: ctx.region,
      resourceName: cert.DomainName,
      state: cert.Status,
      metadata: {
        ...certificateMetadata(cert),
        // Walk outcome, so a partial certificate inventory is visible in the
        // data and not only in a log line.
        acmPages: walk.pages,
        acmWalkComplete: walk.termination === 'complete',
      },
    });
  }
  return out;
}