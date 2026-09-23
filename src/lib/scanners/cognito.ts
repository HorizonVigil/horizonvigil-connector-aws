import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const COGNITO_RESOURCE_TYPES = ['cognito_user_pool', 'cognito_identity_pool'] as const;

/** Describe* follow-ups per region, per pool kind. */
const MAX_DETAILS = 25;

interface UserPoolDescription { Id: string; Name?: string; Status?: string; CreationDate?: number; LastModifiedDate?: number }
interface IdentityPoolShort { IdentityPoolId: string; IdentityPoolName?: string }

export interface UserPoolDetail {
  MfaConfiguration?: string;
  UserPoolAddOns?: { AdvancedSecurityMode?: string };
  Policies?: { PasswordPolicy?: { MinimumLength?: number; RequireUppercase?: boolean; RequireLowercase?: boolean; RequireNumbers?: boolean; RequireSymbols?: boolean; TemporaryPasswordValidityDays?: number } };
  DeletionProtection?: string;
  AdminCreateUserConfig?: { AllowAdminCreateUserOnly?: boolean };
  UserPoolTier?: string;
  Domain?: string;
  CustomDomain?: string;
}
export interface IdentityPoolDetail {
  AllowUnauthenticatedIdentities?: boolean;
  AllowClassicFlow?: boolean;
  CognitoIdentityProviders?: unknown[];
  SupportedLoginProviders?: Record<string, string>;
  OpenIdConnectProviderARNs?: string[];
  SamlProviderARNs?: string[];
}

/** Authentication-posture evidence for a user pool; `detailsCollected: false` means NOT_ASSESSED. */
export function userPoolEvidence(d: UserPoolDetail | null) {
  if (!d) return { detailsCollected: false, mfaConfiguration: null, selfSignUpEnabled: null, advancedSecurityMode: null };
  const pw = d.Policies?.PasswordPolicy;
  return {
    detailsCollected: true,
    // OFF / OPTIONAL / ON.
    mfaConfiguration: d.MfaConfiguration ?? 'OFF',
    // Anyone on the internet can create an account unless admin-only creation is enforced.
    selfSignUpEnabled: !(d.AdminCreateUserConfig?.AllowAdminCreateUserOnly ?? false),
    // Threat protection (FSBP Cognito.1: ENFORCED).
    advancedSecurityMode: d.UserPoolAddOns?.AdvancedSecurityMode ?? 'OFF',
    deletionProtection: d.DeletionProtection ?? 'INACTIVE',
    passwordMinimumLength: pw?.MinimumLength ?? null,
    passwordRequiresUppercase: pw?.RequireUppercase ?? null,
    passwordRequiresLowercase: pw?.RequireLowercase ?? null,
    passwordRequiresNumbers: pw?.RequireNumbers ?? null,
    passwordRequiresSymbols: pw?.RequireSymbols ?? null,
    temporaryPasswordValidityDays: pw?.TemporaryPasswordValidityDays ?? null,
    userPoolTier: d.UserPoolTier ?? null,
    hostedUiDomain: d.CustomDomain ?? d.Domain ?? null,
  };
}

/** Access evidence for an identity pool; `detailsCollected: false` means NOT_ASSESSED. */
export function identityPoolEvidence(d: IdentityPoolDetail | null) {
  if (!d) return { detailsCollected: false, allowUnauthenticatedIdentities: null, allowClassicFlow: null };
  return {
    detailsCollected: true,
    // Guest (unauthenticated) identities receive AWS credentials with no login.
    allowUnauthenticatedIdentities: d.AllowUnauthenticatedIdentities ?? false,
    // The classic (basic) flow lets clients pick the role to assume.
    allowClassicFlow: d.AllowClassicFlow ?? false,
    userPoolProviderCount: d.CognitoIdentityProviders?.length ?? 0,
    socialLoginProviders: Object.keys(d.SupportedLoginProviders ?? {}),
    oidcProviderArns: d.OpenIdConnectProviderARNs ?? [],
    samlProviderArns: d.SamlProviderARNs ?? [],
  };
}

/**
 * Cognito user pools (cognito-idp) and identity pools (cognito-identity) —
 * two separate services sharing one product name.
 *
 * Both lists paginate now (NextToken, 60 per page); failures are reported
 * rather than returned as []. Each pool carries authentication posture from
 * a bounded Describe* pass: MFA, self sign-up, threat protection and
 * password policy for user pools; guest access and classic flow for
 * identity pools. Estimated user counts are NOT stored (they change on their
 * own and would make every pool look modified on every scan).
 */
export async function scanCognito(ctx: ScannerContext): Promise<ScannedResource[]> {
  const idpHost = `cognito-idp.${ctx.region}.amazonaws.com`;
  const identityHost = `cognito-identity.${ctx.region}.amazonaws.com`;

  const [userPools, identityPools] = await Promise.all([
    walkJsonRpc<UserPoolDescription>(ctx, { service: 'cognito-idp', host: idpHost, target: 'AWSCognitoIdentityProviderService.ListUserPools', body: { MaxResults: 60 } }, 'UserPools'),
    walkJsonRpc<IdentityPoolShort>(ctx, { service: 'cognito-identity', host: identityHost, target: 'AWSCognitoIdentityService.ListIdentityPools', body: { MaxResults: 60 } }, 'IdentityPools'),
  ]);
  reportWalk(ctx, userPools, 'cognito-idp', 'ListUserPools');
  reportWalk(ctx, identityPools, 'cognito-identity', 'ListIdentityPools');

  const ups = userPools.items.filter((p) => !!p?.Id);
  const ips = identityPools.items.filter((p) => !!p?.IdentityPoolId);
  const upDetails = new Map<string, UserPoolDetail | null>();
  const ipDetails = new Map<string, IdentityPoolDetail | null>();
  await Promise.all([
    mapWithConcurrency(ups.slice(0, MAX_DETAILS), 4, async (p) => {
      const r = await callJsonApi(ctx.creds, { service: 'cognito-idp', region: ctx.region, host: idpHost, target: 'AWSCognitoIdentityProviderService.DescribeUserPool', body: { UserPoolId: p.Id } });
      upDetails.set(p.Id, r.ok ? ((r.body as { UserPool?: UserPoolDetail })?.UserPool ?? null) : null);
    }),
    mapWithConcurrency(ips.slice(0, MAX_DETAILS), 4, async (p) => {
      const r = await callJsonApi(ctx.creds, { service: 'cognito-identity', region: ctx.region, host: identityHost, target: 'AWSCognitoIdentityService.DescribeIdentityPool', body: { IdentityPoolId: p.IdentityPoolId } });
      ipDetails.set(p.IdentityPoolId, r.ok ? ((r.body as IdentityPoolDetail) ?? null) : null);
    }),
  ]);

  const out: ScannedResource[] = [];
  for (const pool of ups) {
    out.push({
      resourceTypeKey: 'cognito_user_pool', resourceId: pool.Id, region: ctx.region, resourceName: pool.Name,
      state: pool.Status,
      metadata: {
        createdAt: pool.CreationDate, lastModified: pool.LastModifiedDate,
        createdAtIso: toIso(pool.CreationDate), lastModifiedIso: toIso(pool.LastModifiedDate),
        ...userPoolEvidence(upDetails.get(pool.Id) ?? null),
      },
    });
  }
  for (const pool of ips) {
    out.push({
      resourceTypeKey: 'cognito_identity_pool', resourceId: pool.IdentityPoolId, region: ctx.region, resourceName: pool.IdentityPoolName,
      metadata: identityPoolEvidence(ipDetails.get(pool.IdentityPoolId) ?? null),
    });
  }
  return out;
}