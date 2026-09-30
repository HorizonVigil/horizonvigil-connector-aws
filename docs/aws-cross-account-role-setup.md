# Connecting AWS without access keys

HorizonVigil can read your AWS account through an IAM **role** instead of an
IAM user's access key and secret. Nothing long-lived is created, stored, or
shared — in either direction.

| | Access keys | Cross-account role |
|---|---|---|
| What you create | An IAM user + key pair | An IAM role |
| What HorizonVigil stores | Your secret key, encrypted | Nothing |
| Rotation | Yours to do, every 90 days | None — credentials last 15 minutes |
| If HorizonVigil were breached | Your key is exposed | There is no key to expose |
| Revoking access | Delete the key | Delete the role |

---

## How it works

HorizonVigil runs on Google Cloud Run. AWS accepts Google as a federated
identity provider natively, and `AssumeRoleWithWebIdentity` is an unsigned
call — AWS itself documents that it "does not require the use of AWS security
credentials."

So the sequence is:

1. Google signs a short-lived token asserting *"this is HorizonVigil's
   workload."*
2. HorizonVigil presents that token to AWS STS along with your role's ARN.
3. AWS checks the token's signature against Google, checks the claims against
   **your** trust policy, and returns credentials valid for 15 minutes.

There is no AWS access key anywhere in that sequence — not in HorizonVigil, not
in your account.

### What your trust policy pins

Two conditions, and both matter:

```json
"Condition": {
  "StringEquals": {
    "accounts.google.com:sub":  "<HorizonVigil's service account ID>",
    "accounts.google.com:oaud": "<your connection's External ID>"
  }
}
```

- **`sub`** pins *which* Google workload may assume the role. Without it, any
  Google-hosted workload on the internet could.
- **`oaud`** pins *which of your connections* the token was minted for.
  HorizonVigil mints each token with your External ID as its audience, so this
  is the external-ID guarantee — carried as a claim Google signed rather than a
  value the caller chose.

`sub` alone is not enough: the same service account serves every customer, so
without `oaud` a token minted for one customer would satisfy another's trust
policy.

---

## Setup

### 1. Get HorizonVigil's service account ID

In HorizonVigil, open **Cloud Accounts → Add AWS Account → Cross-Account
Role**. The service account ID is shown there.

It is read from a live token each time it is displayed, so it cannot drift from
the identity actually presented to AWS. It is a public identifier, not a
secret.

### 2. Deploy the role

Download `templates/horizonvigil-scan-role-stackset.yaml` and deploy it, either
as a normal stack in one account or as a **StackSet** across your
organization.

| Parameter | Value |
|---|---|
| `TrustMode` | `WebIdentity` (the default) |
| `PlatformGoogleSubject` | The service account ID from step 1 |
| `ExternalId` | The External ID HorizonVigil shows for this connection |
| `PlatformAccountId` | Leave as-is — only used by `TrustMode: PlatformAccount` |

Tick *"I acknowledge that AWS CloudFormation might create IAM resources"*, then
create the stack. The role is named `HorizonVigilRead` — fixed, not
auto-generated, so HorizonVigil can derive every member account's role ARN from
its account ID.

### 3. Connect

Enter your AWS account ID in HorizonVigil and choose **Cross-Account Role**.
HorizonVigil assumes the role immediately and confirms which account answered
before saving anything — a role that doesn't yet exist, or a trust policy that
doesn't match, is reported at that point rather than stored and discovered
later.

---

## If your security policy requires an AWS principal

Some organizations will not write `accounts.google.com` into a trust policy.
Deploy with `TrustMode: PlatformAccount` instead, and the role trusts a
HorizonVigil-owned AWS account with the classic `sts:ExternalId` condition.

This is the older model and it is less safe for both sides: it requires
HorizonVigil to hold a long-lived AWS access key, and a single compromised key
would reach every customer who chose this mode. Prefer `WebIdentity` unless you
have a specific reason not to.

---

## Troubleshooting

**`AccessDenied` when connecting**

The role exists but its trust policy didn't match. Check, in order:

1. `PlatformGoogleSubject` matches the value HorizonVigil currently shows.
2. `ExternalId` in the stack matches the one shown for *this* connection — they
   are per-connection, and using another connection's will fail here.
3. The trust policy's action is `sts:AssumeRoleWithWebIdentity`, not
   `sts:AssumeRole`. They are different actions and the role needs the one
   matching its `TrustMode`.

**`IDPRejectedClaim`**

Almost always the audience: the `accounts.google.com:oaud` condition does not
equal the External ID HorizonVigil is minting tokens for.

**The connect screen says cross-account roles are not available**

The capability is switched off in that deployment. It is deliberately a
deployment decision, not something that turns itself on when the code ships.

**Connection worked, then stopped**

Credentials last 15 minutes and are re-obtained per operation, so an expiry is
not a thing you need to act on. A sudden failure usually means the role or its
trust policy changed — check CloudTrail in your account for
`AssumeRoleWithWebIdentity` denials.

---

## What the role can do

Exactly what the access-key path can do: read. The permission policy is the
same one documented in the connect wizard — no write, no delete, no
credential-producing actions, and a single `s3:GetObject` scoped by ARN to the
Cost & Usage Report bucket.

Deleting the CloudFormation stack removes the role and ends HorizonVigil's
access immediately. There is nothing else to revoke.
