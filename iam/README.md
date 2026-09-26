# Warden IAM policy: the second lock

Warden has **two independent locks**. A change goes through only if both allow it.

1. **Warden's code (first lock).** Before any change, the MCP server checks the plan lock (only ids from a fresh scan, with the action the scan proposed), batch limits (irreversible actions take exactly one id), the freeze switch, the scope tag, and protected, managed-by-code and suspicious tags. It then re-checks each resource just before acting. The LLM cannot change any of this; every check runs in Python.
2. **AWS IAM (second lock).** `warden-policy.json` gives the Warden identity only the API calls Warden needs. It also has explicit **Deny** statements that AWS enforces even if Warden had a bug:
   - `ec2:TerminateInstances` is always denied.
   - `DeleteVolume`, `DeleteSnapshot`, `StopInstances` and `ReleaseAddress` are denied on resources whose `env`, `environment` or `stage` tag starts with `prod` or `prd` (lower, Title or UPPER case, so `production`, `Prod-EU` and `PRD` too; IAM is slightly stricter than the code here), on resources that carry a `legal-hold`, `legal_hold` or `legalhold` tag (any value), a `dr` tag (any value except `false`/`no`/`0`) or `role=dr`, and on resources tagged `warden:protect=true`.
   - Tags can only be written two ways: any tags while a snapshot or volume is being **created** (Warden's backups and restores copy the original tags), or later only keys starting with `warden:`. `DeleteTags` is also limited to `warden:` keys. So Warden can never rewrite or remove a protection tag such as `env` or `legal-hold`.

   In IAM an explicit Deny always beats an Allow, so these holds apply even if someone later attaches a broader policy to the same identity.

## What it allows

| Purpose | Actions |
| --- | --- |
| Discovery (read-only) | `ec2:Describe*`, `ec2:ListSnapshotsInRecycleBin`, `cloudwatch:GetMetricStatistics`, `cloudwatch:GetMetricData`, `cloudtrail:LookupEvents`, `rbin:ListRules`, `rbin:GetRule`, `sts:GetCallerIdentity` |
| Backup and restore | `ec2:CreateSnapshot`, `ec2:CreateVolume`, `ec2:RestoreSnapshotFromRecycleBin`, `ec2:StartInstances` |
| Tagging (volumes, snapshots and instances only) | `ec2:CreateTags` (any keys only on create; afterwards `warden:*` keys only), `ec2:DeleteTags` (`warden:*` keys only: undo removes Warden's bookkeeping tags) |
| Encrypted volumes | `kms:CreateGrant`, `kms:Decrypt`, `kms:DescribeKey`, `kms:GenerateDataKeyWithoutPlaintext`, `kms:ReEncrypt*`, only when called **through EBS** (`kms:ViaService = ec2.*.amazonaws.com`), so `restore_volume` can recreate a volume encrypted with a customer-managed key |
| Cleanup | `ec2:DeleteVolume`, `ec2:DeleteSnapshot`, `ec2:StopInstances`, `ec2:ReleaseAddress` |

There is no S3, IAM or `TerminateInstances` permission, and no permission to create, change or delete KMS keys (keys are only used through EBS). For a customer-managed key, its key policy must also let this identity use it (the default key policy delegates to IAM). Warden cannot create the Recycle Bin rule itself. An admin creates it once (see below).

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

Reversible snapshot cleanup (`recycle_snapshots`) needs a Recycle Bin retention rule that keeps snapshots tagged `warden:recycle=true` for at least 7 days. Warden checks each snapshot against the rule: a Region-level rule whose exclusion tags match a snapshot, or a rule shorter than 7 days, does not count, and that snapshot is offered only as a permanent, one-at-a-time deletion. An admin (not Warden) creates it once per region:

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
