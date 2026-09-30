# Onboarding hundreds or thousands of AWS accounts

Connecting accounts one at a time stops working somewhere around a dozen. For
an AWS Organization, you deploy **one StackSet** and then import every member
account in a single call — you never touch the member accounts individually.

Three steps, whatever the account count:

1. Connect your **management account** normally, once.
2. Deploy the role as a **StackSet** across the Organization or an OU.
3. **Import** — HorizonVigil reads the Organization and creates a connection
   per account.

---

## 1. Connect the management account

Use the normal Add AWS Account flow for your AWS Organizations **management
account** (or a delegated administrator). This is the only account you connect
by hand. HorizonVigil borrows this connection's own credentials for one
`organizations:ListAccounts` call — it does not get a second credential path.

## 2. Deploy the role to every member account

Get your organization's External ID:

```
GET /api/aws-accounts/organizations/external-id
```

It is generated once per organization and never regenerated, because every
member account's trust policy has to pin the same value forever.

Then deploy `templates/horizonvigil-scan-role-stackset.yaml` as a **StackSet**
targeting your Organization root or specific OUs:

| Parameter | Value |
|---|---|
| `ExternalId` | From the call above |
| `TrustMode` | `WebIdentity` (default) |
| `PlatformGoogleSubject` | Shown in the connect screen |

Enable **automatic deployment** on the StackSet so accounts added to the
Organization later get the role without you doing anything.

Every account gets a role at exactly `HorizonVigilRead`. The name is fixed on
purpose — that is what lets the import derive each account's role ARN from its
account ID alone, instead of asking you for it 800 times.

## 3. Preview, then import

**Preview first.** It creates nothing:

```
GET /api/aws-accounts/accounts/bulk-import/preview?managementConnectionId=<id>
```

```json
{
  "scope":               { "parentId": null, "description": "entire organization" },
  "total":               847,
  "active":              820,
  "inactive":            27,
  "alreadyConnected":    12,
  "importable":          808,
  "plan":                { "used": 12, "included": 50, "afterImport": 820, "overBy": 770 },
  "sample":              [ … ]
}
```

`plan.afterImport` is where the import leaves you against your subscription,
not where you are now. Suspended and closed accounts are excluded.

Then import:

```
POST /api/aws-accounts/accounts/bulk-import-from-organization
{ "managementConnectionId": "<id>", "environment": "production" }
```

Requires the **org owner** role — deliberately stricter than connecting one
account, because this can create hundreds of connections at once. Rate limited
to 3 per hour.

---

## Organizations larger than 2,000 accounts

`ListAccounts` tops out at 2,000 accounts per call, so above that an
Organization cannot be read in one request at all. Import it **one
organizational unit at a time** by passing `parentId`:

```
GET  …/bulk-import/preview?managementConnectionId=<id>&parentId=ou-abc1-def2
POST …/bulk-import-from-organization   { "managementConnectionId": "<id>", "parentId": "ou-abc1-def2" }
```

Get OU ids from `GET /api/aws-accounts/organizations/hierarchy`.

`parentId` returns an OU's **direct** member accounts, not nested ones — so
"import this OU" means the same thing regardless of how deep your tree goes.
Import each OU you want.

Scoping is also useful well below 2,000: it is how you onboard Production
without also onboarding every sandbox, and how you give different OUs
different `environment` values.

---

## What the response tells you

```json
{
  "imported":   806,
  "attempted":  808,
  "failed":     2,
  "failedBatches": [ { "accounts": 2, "firstAccountId": "…", "error": "…" } ],
  "planLimitWarning": "This import takes you to 818 cloud accounts against a plan that includes 50.",
  "nextStep": "Connections are queued as pending…"
}
```

`attempted` and `failed` are always reported, so a partial import can never be
mistaken for a complete one. Accounts are inserted in batches; a batch that
fails is recorded and the rest still import, so you re-run for the remainder
rather than starting over.

## What happens after the import

Connections are created **pending**, not connected. The import does not assume
800 roles — that does not belong in one HTTP request. First scans run on the
scheduled internal sweep, and that is where a role whose trust policy does not
match surfaces as a connection error on that specific account.

So: a successful import means *800 connections were created*, not *800 roles
work*. Check the account list after the first sweep.

---

## Troubleshooting

**`ListAccounts failed`** — the connection you passed is probably not the
management account. Only the management account (or a delegated administrator)
can list an Organization.

**`could not be read completely`** — more accounts than a single call can read.
Scope by OU, as above.

**Every imported account errors on first scan** — the StackSet did not reach
them, or its parameters don't match. Check `ExternalId` matches the value from
step 2, and `PlatformGoogleSubject` matches what the connect screen shows.

**Some accounts were skipped** — already connected (they are not duplicated),
or not `ACTIVE`. Both counts are in the response.

**Cross-account role is unavailable** — bulk import depends on it, so it is
refused when that capability is switched off in the deployment.
