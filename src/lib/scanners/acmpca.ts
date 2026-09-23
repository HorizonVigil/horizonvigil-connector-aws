import { reportWalk, toIso, walkJsonRpc } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'ACMPrivateCA';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ACMPCA_RESOURCE_TYPES = ['acm_pca'] as const;

interface CertificateAuthoritySubject {
  CommonName?: string; Organization?: string; OrganizationalUnit?: string;
  Country?: string; State?: string; Locality?: string;
}
interface CertificateAuthorityConfiguration {
  KeyAlgorithm?: string; SigningAlgorithm?: string; Subject?: CertificateAuthoritySubject;
}
interface RevocationConfiguration {
  CrlConfiguration?: { Enabled?: boolean; ExpirationInDays?: number; S3BucketName?: string; S3ObjectAcl?: string };
  OcspConfiguration?: { Enabled?: boolean };
}
export interface CertificateAuthority {
  Arn: string; OwnerAccount?: string; Type?: string; Status?: string;
  CertificateAuthorityConfiguration?: CertificateAuthorityConfiguration;
  RevocationConfiguration?: RevocationConfiguration;
  CreatedAt?: number; LastStateChangeAt?: number; NotBefore?: number; NotAfter?: number;
  RestorableUntil?: number;
  FailureReason?: string; UsageMode?: string; KeyStorageSecurityStandard?: string; Serial?: string;
}

/**
 * Evidence for one private CA. Raw epoch values are kept under their
 * original keys for existing consumers; *Iso keys are the normalized form.
 */
export function caMetadata(ca: CertificateAuthority) {
  const crl = ca.RevocationConfiguration?.CrlConfiguration;
  return {
    type: ca.Type,
    ownerAccount: ca.OwnerAccount,
    keyAlgorithm: ca.CertificateAuthorityConfiguration?.KeyAlgorithm,
    signingAlgorithm: ca.CertificateAuthorityConfiguration?.SigningAlgorithm,
    subjectOrganization: ca.CertificateAuthorityConfiguration?.Subject?.Organization ?? null,
    createdAt: ca.CreatedAt,
    lastStateChangeAt: ca.LastStateChangeAt,
    notBefore: ca.NotBefore,
    notAfter: ca.NotAfter,
    createdAtIso: toIso(ca.CreatedAt),
    notBeforeIso: toIso(ca.NotBefore),
    notAfterIso: toIso(ca.NotAfter),
    restorableUntilIso: toIso(ca.RestorableUntil),
    failureReason: ca.FailureReason,
    usageMode: ca.UsageMode,
    keyStorageSecurityStandard: ca.KeyStorageSecurityStandard,
    serial: ca.Serial,
    // Revocation: a CA whose issued certificates cannot be revoked is a gap.
    crlEnabled: crl?.Enabled ?? false,
    crlS3BucketName: crl?.S3BucketName ?? null,
    // BUCKET_OWNER_FULL_CONTROL keeps the CRL bucket private; PUBLIC_READ exposes it.
    crlS3ObjectAcl: crl?.S3ObjectAcl ?? null,
    ocspEnabled: ca.RevocationConfiguration?.OcspConfiguration?.Enabled ?? false,
  };
}

/**
 * ACM Private Certificate Authority — a separate API from regular ACM
 * (acm.ts): this inventories the private CAs themselves.
 *
 * ListCertificateAuthorities is paginated (NextToken). The previous version
 * read one page and treated a failure as "no CAs", both of which finalize
 * reads as deletion. It now reads every page and reports an incomplete walk.
 * Each summary already carries RevocationConfiguration, so revocation
 * evidence costs no extra call.
 */
export async function scanAcmPca(ctx: ScannerContext): Promise<ScannedResource[]> {
  const walk = await walkJsonRpc<CertificateAuthority>(ctx, {
    service: 'acm-pca', host: `acm-pca.${ctx.region}.amazonaws.com`,
    target: `${TARGET_PREFIX}.ListCertificateAuthorities`, body: { MaxResults: 100 },
  }, 'CertificateAuthorities');
  reportWalk(ctx, walk, 'acm-pca', 'ListCertificateAuthorities');

  const seen = new Set<string>();
  const out: ScannedResource[] = [];
  for (const ca of walk.items) {
    if (!ca?.Arn || seen.has(ca.Arn)) continue;
    seen.add(ca.Arn);
    out.push({
      resourceTypeKey: 'acm_pca', resourceId: ca.Arn, region: ctx.region,
      resourceName: ca.CertificateAuthorityConfiguration?.Subject?.CommonName ?? ca.Arn,
      state: ca.Status,
      metadata: caMetadata(ca),
      relationships: { crlS3BucketName: ca.RevocationConfiguration?.CrlConfiguration?.S3BucketName ?? null },
    });
  }
  return out;
}