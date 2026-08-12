import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SERVICECATALOG_RESOURCE_TYPES = ['service_catalog_portfolio', 'servicecatalog_product'] as const;

interface PortfolioDetail { Id: string; ARN?: string; DisplayName?: string; Description?: string; ProviderName?: string; CreatedTime?: number }
interface ListPortfoliosResponse { PortfolioDetails?: PortfolioDetail[] }
interface ProductViewSummary { ProductId: string; Name?: string; Owner?: string; Type?: string }
interface ProductViewDetail { ProductViewSummary?: ProductViewSummary; Status?: string; ProductARN?: string; CreatedTime?: number }
interface SearchProductsAsAdminResponse { ProductViewDetails?: ProductViewDetail[] }

/**
 * Service Catalog — JSON 1.1 target-header protocol (confirmed bare-JSON
 * request body, no URI path, against AWS's API reference), but the exact
 * X-Amz-Target service prefix is a best-effort guess against AWS's internal
 * naming convention, not spelled out in the public docs — UNVERIFIED
 * against a real account, same caveat as cloudhsm.ts/computeoptimizer.ts.
 */
export async function scanServiceCatalog(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `servicecatalog.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'servicecatalog', region: ctx.region, host, target: `AWS242ServiceCatalogService.${target}`, body });

  const out: ScannedResource[] = [];

  const portfoliosResult = await call('ListPortfolios');
  if (!portfoliosResult.ok) {
    console.error(`Service Catalog ListPortfolios failed in ${ctx.region} (continuing without it): ${portfoliosResult.errorMessage ?? portfoliosResult.errorCode ?? portfoliosResult.status}`);
    return out;
  }
  for (const p of (portfoliosResult.body as ListPortfoliosResponse).PortfolioDetails ?? []) {
    out.push({
      resourceTypeKey: 'service_catalog_portfolio', resourceId: p.ARN ?? p.Id, region: ctx.region, resourceName: p.DisplayName,
      metadata: { description: p.Description, providerName: p.ProviderName, createdTime: p.CreatedTime },
    });
  }

  const productsResult = await call('SearchProductsAsAdmin');
  for (const p of (productsResult.ok ? (productsResult.body as SearchProductsAsAdminResponse).ProductViewDetails : []) ?? []) {
    if (!p.ProductViewSummary) continue;
    out.push({
      resourceTypeKey: 'servicecatalog_product', resourceId: p.ProductARN ?? p.ProductViewSummary.ProductId, region: ctx.region, resourceName: p.ProductViewSummary.Name,
      state: p.Status, metadata: { owner: p.ProductViewSummary.Owner, type: p.ProductViewSummary.Type, createdTime: p.CreatedTime },
    });
  }

  return out;
}
