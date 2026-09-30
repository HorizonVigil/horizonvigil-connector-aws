# Setting up cost data for AWS

HorizonVigil shows two different kinds of cost information, and they need
different setup.

| What you see | Where it comes from | Setup needed |
|---|---|---|
| Account and service totals | Cost Explorer API | None — the scan role already has it |
| **Per-resource cost** (this EC2 instance cost $41.30 last month) | **Cost & Usage Report** | **This page** |

Only the Cost & Usage Report (CUR) contains a line per resource per day. Cost
Explorer returns aggregates, so without a CUR, HorizonVigil can tell you what
a *service* cost but not what a *resource* cost — and rightsizing advice with
no dollar figure attached to the actual resource is not worth acting on.

If you do not set this up, HorizonVigil says so explicitly. It does not show
`$0`.

---

## Before you start

**Use your management (payer) account.** AWS consolidates billing at the
payer, so one report there already covers every member account in the
organization. You do not need one per account, and creating one per account
multiplies your S3 bill for duplicated data.

**Use us-east-1.** AWS Data Exports is a us-east-1 service. The report
*describes* spend in every region; the export definition itself lives in
N. Virginia.

**You need permission to create IAM roles, S3 buckets, and Lambda functions**
in that account, plus the Billing permissions to create a data export.

---

## Option A — let HorizonVigil create the report (recommended)

One CloudFormation stack. Nothing to copy back.

1. Download `templates/horizonvigil-cur-setup.yaml`.
2. Open the **CloudFormation console in your management account**, switched to
   **US East (N. Virginia)**.
3. **Create stack → With new resources (standard) → Upload a template file**,
   choose the file, **Next**.
4. Stack name: `horizonvigil-cur`. Leave every parameter at its default unless
   you have a reason — the defaults are what HorizonVigil looks for.
5. **Next**, **Next**, tick *"I acknowledge that AWS CloudFormation might
   create IAM resources"*, **Create stack**.
6. Wait for `CREATE_COMPLETE` (2–4 minutes).

That is the whole setup. **There is nothing to paste into HorizonVigil.** The
bucket is named `horizonvigil-cur-<your-account-id>`, which HorizonVigil
derives from your account ID, and the report is found automatically.

### What the stack creates

| Resource | Why |
|---|---|
| S3 bucket `horizonvigil-cur-<account-id>` | Where AWS delivers the report. Encrypted, public access blocked, plaintext transport denied. |
| Bucket policy | Lets the AWS billing service write into it — and only this account's billing service. |
| Data export `horizonvigil-cur` | The CUR 2.0 report itself: daily, CSV + gzip, resource IDs included. |
| Lambda + role | CloudFormation has no native resource type for Data Exports, so a small function creates it. Its permissions cover only this one export. |

The bucket is set to **Retain**: deleting the stack stops new deliveries but
does not destroy your billing history.

---

## Option B — you already have a Cost & Usage Report

HorizonVigil will find an existing report on its own. You only need to grant
read access to the bucket it already lives in.

1. Find the bucket name: **Billing console → Data Exports** (or **Cost &
   Usage Reports** for a legacy report) → open the report → note the S3 bucket.
2. Deploy `templates/horizonvigil-scan-role-stackset.yaml` and set the
   **`AdditionalCurBucketName`** parameter to that bucket name.

That grants read on that bucket **and nothing else**.

Your existing report must have **resource IDs included**. A report without
them cannot produce per-resource cost — that is a property of the report, not
of HorizonVigil. If yours does not have them, either enable it on the existing
report or use Option A.

---

## What happens next, and when

| When | What |
|---|---|
| Immediately | The stack completes. There is no cost data yet. |
| **Up to 24 hours** | AWS delivers the first report. This is AWS's schedule and cannot be accelerated. |
| After first delivery | HorizonVigil ingests it on the next cost sync. Per-resource cost appears. |
| Daily thereafter | AWS refreshes the current billing period at least once a day. |

Until the first delivery lands, HorizonVigil shows cost as **not yet
delivered**, with the reason. It will not show `$0`.

AWS may restate the previous billing period for up to two weeks after it ends.
HorizonVigil re-reads and corrects rather than keeping the first answer.

---

## Checking it worked

**In AWS** — the report was created:
Billing console → **Data Exports** → you should see `horizonvigil-cur`.

**In AWS** — the data has been delivered:
S3 → `horizonvigil-cur-<account-id>` →
`horizonvigil/horizonvigil-cur/metadata/BILLING_PERIOD=YYYY-MM/`
A `Manifest.json` here means AWS has finished delivering that period. AWS
writes the manifest **last**, on purpose, so its presence means the data files
are complete.

**In HorizonVigil** — open the AWS account and check the cost panel. If
something is missing it names what is missing.

---

## Troubleshooting

**Stack fails with `Invalid principal in policy`**
The billing service principals are not available in your partition (for
example AWS GovCloud or China). Data Exports is not offered in every
partition; use Option B with a report you create by hand there.

**Stack fails on the `CurExport` custom resource**
Open the Lambda's log group, `/aws/lambda/HorizonVigilCurCreator-<stack>`. The
failure reason is written there in full. The most common cause is that the
deploying principal lacks Billing permissions, which are separate from
administrator access in accounts where billing is restricted.

**`An export with this name already exists`**
Re-deploy with a different `ExportName`, then enter that name in HorizonVigil
so it looks for the right one.

**Stack completed, but no data after 48 hours**
Check the Data Export's status in the Billing console. If it shows a delivery
failure, the bucket policy is usually the cause — confirm the stack's
`CurBucketPolicy` still exists and was not replaced by a bucket-level policy
change elsewhere.

**Cost still shows as unavailable in HorizonVigil after data has landed**
The scan role needs read access to the bucket. If you deployed the CUR stack
but not the role StackSet — or deployed the role StackSet *before* this
document existed — redeploy
`templates/horizonvigil-scan-role-stackset.yaml`; earlier versions did not
grant CUR read at all.

---

## What HorizonVigil can read

The role gets exactly two things for cost:

- **Finding the report** — `cur:DescribeReportDefinitions`,
  `bcm-data-exports:ListExports`, `bcm-data-exports:GetExport`. These read the
  export *definition* (where it is written, under what name). They read no
  billing data.
- **Reading the report** — `s3:GetObject` and `s3:ListBucket`, scoped to the
  CUR bucket by ARN.

That `s3:GetObject` is the **only** grant in the entire role that can read the
contents of an object. Every other S3 permission it holds reads bucket
*settings* — encryption, lifecycle, public-access configuration — which is
what security posture checks need. If you want to verify this rather than take
our word for it, search the template for `s3:GetObject`: there is one, and its
`Resource` names the CUR bucket.

The report itself is billing data. It contains resource identifiers, usage
quantities, costs and any tags you have applied. It does not contain the
contents of your resources.
