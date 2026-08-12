import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const COGNITO_RESOURCE_TYPES = ['cognito_user_pool', 'cognito_identity_pool'] as const;

interface UserPoolDescription {
  Id: string; Name?: string; Status?: string; CreationDate?: number; LastModifiedDate?: number;
}
interface IdentityPoolShort {
  IdentityPoolId: string; IdentityPoolName?: string;
}

/**
 * Two distinct services sharing one catalog category — user pools
 * (cognito-idp) and identity pools (cognito-identity) are unrelated
 * resources under the same product name, each with its own signing service
 * name and endpoint, same split the catalog itself already makes
 * (service='cognito-idp' vs 'cognito-identity').
 */
export async function scanCognito(ctx: ScannerContext): Promise<ScannedResource[]> {
  const out: ScannedResource[] = [];

  const idpEndpoint = `cognito-idp.${ctx.region}.amazonaws.com`;
  const userPools = await callJsonApi(ctx.creds, {
    service: 'cognito-idp', region: ctx.region, host: idpEndpoint,
    target: 'AWSCognitoIdentityProviderService.ListUserPools', body: { MaxResults: 60 },
  });
  if (!userPools.ok) {
    console.error(`Cognito ListUserPools failed in ${ctx.region} (continuing without it): ${userPools.errorMessage ?? userPools.errorCode ?? userPools.status}`);
  } else {
    for (const pool of (userPools.body as { UserPools?: UserPoolDescription[] }).UserPools ?? []) {
      out.push({
        resourceTypeKey: 'cognito_user_pool', resourceId: pool.Id, region: ctx.region, resourceName: pool.Name,
        state: pool.Status, metadata: { createdAt: pool.CreationDate, lastModified: pool.LastModifiedDate },
      });
    }
  }

  const identityEndpoint = `cognito-identity.${ctx.region}.amazonaws.com`;
  const identityPools = await callJsonApi(ctx.creds, {
    service: 'cognito-identity', region: ctx.region, host: identityEndpoint,
    target: 'AWSCognitoIdentityService.ListIdentityPools', body: { MaxResults: 60 },
  });
  if (!identityPools.ok) {
    console.error(`Cognito ListIdentityPools failed in ${ctx.region} (continuing without it): ${identityPools.errorMessage ?? identityPools.errorCode ?? identityPools.status}`);
  } else {
    for (const pool of (identityPools.body as { IdentityPools?: IdentityPoolShort[] }).IdentityPools ?? []) {
      out.push({
        resourceTypeKey: 'cognito_identity_pool', resourceId: pool.IdentityPoolId, region: ctx.region, resourceName: pool.IdentityPoolName,
      });
    }
  }

  return out;
}
