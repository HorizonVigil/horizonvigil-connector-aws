import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CertificateManager';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ACM_RESOURCE_TYPES = ['acm_certificate'] as const;

interface CertificateSummary {
  CertificateArn: string; DomainName?: string; Status?: string; Type?: string; NotAfter?: number; InUse?: boolean;
}

/** ListCertificates — one JSON-RPC call; its CertificateSummary entries already include Status, so no per-certificate DescribeCertificate follow-up is needed for basic inventory. */
export async function scanAcm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `acm.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, { service: 'acm', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListCertificates`, body: {} });
  if (!result.ok) {
    console.error(`ACM ListCertificates failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const certs = (result.body as { CertificateSummaryList?: CertificateSummary[] }).CertificateSummaryList ?? [];
  return certs.map((cert) => ({
    resourceTypeKey: 'acm_certificate', resourceId: cert.CertificateArn, region: ctx.region, resourceName: cert.DomainName,
    state: cert.Status, metadata: { type: cert.Type, notAfter: cert.NotAfter, inUse: cert.InUse },
  }));
}
