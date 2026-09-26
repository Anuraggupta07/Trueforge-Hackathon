# Warden IAM policy: the second lock

Warden has **two independent locks**. A change goes through only if both allow it.

1. **Warden's code (first lock).** Before any change, the MCP server checks the plan lock (only ids from a fresh scan, with the action the scan proposed), batch limits (irreversible actions take exactly one id), the freeze switch, the scope tag, and protected, managed-by-code and suspicious tags. It then re-checks each resource just before acting. The LLM cannot change any of this; every check runs in Python.
2. **AWS IAM (second lock).** `warden-policy.json` gives the Warden identity only the API calls Warden needs. It also has explicit **Deny** statements that AWS enforces even if Warden had a bug:
   - `ec2:TerminateInstances` is always denied.
   - `DeleteVolume`, `DeleteSnapshot`, `StopInstances` and `ReleaseAddress` are denied on resources tagged `env` or `environment` = `production` / `prod` (any case), on resources that carry a `legal-hold` or `legal_hold` tag (any value), and on resources tagged `warden:protect=true`.

   In IAM an explicit Deny always beats an Allow, so these holds apply even if someone later attaches a broader policy to the same identity.

## What it allows

| Purpose | Actions |
| --- | --- |
| Discovery (read-only) | `ec2:Describe*`, `ec2:ListSnapshotsInRecycleBin`, `cloudwatch:GetMetricStatistics`, `cloudwatch:GetMetricData`, `cloudtrail:LookupEvents`, `rbin:ListRules`, `rbin:GetRule`, `sts:GetCallerIdentity` |
| Backup and restore | `ec2:CreateSnapshot`, `ec2:CreateVolume`, `ec2:RestoreSnapshotFromRecycleBin`, `ec2:StartInstances` |
| Tagging (volumes, snapshots and instances only) | `ec2:CreateTags` |
| Cleanup | `ec2:DeleteVolume`, `ec2:DeleteSnapshot`, `ec2:StopInstances`, `ec2:ReleaseAddress` |

There is no KMS, S3, IAM or `TerminateInstances` permission. Warden cannot create the Recycle Bin rule itself. An admin creates it once (see below).

## Attach it

Use a dedicated IAM user or role for Warden. Do not reuse an admin identity.

```bash
aws iam create-policy --policy-name WardenCostCleanup \
  --policy-document file://iam/warden-policy.json

# Role (preferred, e.g. assumed via SSO or an instance profile):
aws iam attach-role-policy --role-name warden \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/WardenCostCleanup

# ...or a user:
aws iam attach-user-policy --user-name warden \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/WardenCostCleanup
```

Run Warden with that identity (`AWS_PROFILE=warden`, or SSO). Never put keys in `.env`.

## One-time admin setup: Recycle Bin rule

Reversible snapshot cleanup (`recycle_snapshots`) needs a Recycle Bin retention rule that keeps snapshots tagged `warden:recycle=true` for 7 days. An admin (not Warden) creates it once per region:

```bash
aws rbin create-rule --resource-type EBS_SNAPSHOT \
  --retention-period RetentionPeriodValue=7,RetentionPeriodUnit=DAYS \
  --resource-tags ResourceTagKey=warden:recycle,ResourceTagValue=true \
  --description "Warden: keep recycled snapshots restorable for 7 days"
```

Without this rule, Warden offers only the irreversible `delete_snapshot_permanently`, one snapshot at a time.

## Check it

Use the IAM policy simulator, or a dry run. For example, stopping a `env=prod` instance should return `UnauthorizedOperation`:

```bash
aws ec2 stop-instances --instance-ids i-0123456789abcdef0 --dry-run
```
