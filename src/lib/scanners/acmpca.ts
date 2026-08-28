import { callJsonApi } from '../awsApi';
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
interface CertificateAuthority {
  Arn: string; OwnerAccount?: string; Type?: string; Status?: string;
  CertificateAuthorityConfiguration?: CertificateAuthorityConfiguration;
  CreatedAt?: number; LastStateChangeAt?: number; NotBefore?: number; NotAfter?: number;
  FailureReason?: string; UsageMode?: string; KeyStorageSecurityStandard?: string; Serial?: string;
}
interface ListCertificateAuthoritiesResponse {
  CertificateAuthorities?: CertificateAuthority[]; NextToken?: string;
}

/**
 * ACM Private Certificate Authority (ACM PCA) — the private-CA management
 * service, a genuinely separate AWS API from regular ACM (acm.ts), sharing
 * only the "ACM" name prefix. Regular ACM (acm.ts) inventories issued
 * public/private *certificates*; this scanner inventories the private
 * *certificate authorities* themselves (host `acm-pca.<region>`, target
 * prefix `ACMPrivateCA`, its own service id for SigV4) — deliberately kept
 * as its own file rather than folded into acm.ts.
 *
 * ListCertificateAuthorities is a paginated operation (NextToken), but a
 * single page at MaxResults=100 is acceptable for a first pass per the
 * product's own scope for this scanner — most accounts have far fewer than
 * 100 private CAs.
 *
 * UNVERIFIED against a real account's actual response shape until this runs
 * against a live connection and gets checked -- same disclosed-uncertainty
 * convention as inspector2.ts (request/response shape here is taken from the
 * AWS API reference docs, not exercised against a live ACM PCA account).
 */
export async function scanAcmPca(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `acm-pca.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, {
    service: 'acm-pca', region: ctx.region, host: endpoint,
    target: `${TARGET_PREFIX}.ListCertificateAuthorities`, body: { MaxResults: 100 },
  });
  if (!result.ok) {
    console.error(`ACM PCA ListCertificateAuthorities failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const authorities = (result.body as ListCertificateAuthoritiesResponse).CertificateAuthorities ?? [];
  return authorities.map((ca) => ({
    resourceTypeKey: 'acm_pca', resourceId: ca.Arn, region: ctx.region,
    resourceName: ca.CertificateAuthorityConfiguration?.Subject?.CommonName ?? ca.Arn,
    state: ca.Status,
    metadata: {
      type: ca.Type,
      ownerAccount: ca.OwnerAccount,
      keyAlgorithm: ca.CertificateAuthorityConfiguration?.KeyAlgorithm,
      signingAlgorithm: ca.CertificateAuthorityConfiguration?.SigningAlgorithm,
      createdAt: ca.CreatedAt,
      lastStateChangeAt: ca.LastStateChangeAt,
      notBefore: ca.NotBefore,
      notAfter: ca.NotAfter,
      failureReason: ca.FailureReason,
      usageMode: ca.UsageMode,
      keyStorageSecurityStandard: ca.KeyStorageSecurityStandard,
      serial: ca.Serial,
    },
  }));
}
