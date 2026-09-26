# Warden: cloud cost cleanup that proves it's safe first

**Warden proves that cloud waste is safe to remove, removes it reversibly with human approval, and tells you how to stop it coming back.**

Built on [TrueForge](https://github.com/truefoundry/trueforge) for **Agents That Act**, a TrueFoundry × Polaris hackathon (26 September 2026).

> 🚧 Work in progress. Setup and run instructions will be added as the build lands.

## The problem

Companies waste about **29% of their cloud spend** ([Flexera 2026 State of the Cloud](https://www.flexera.com/blog/finops/flexera-2026-state-of-the-cloud-report-the-convergence-of-cloud-and-value/)). Finding the waste is a solved problem. Cleanups still fail for three reasons:

1. **Fear.** Deleting is permanent, and deleting the wrong thing causes outages. At Atlassian in 2022, a cleanup script given the wrong IDs deleted 883 customer sites.
2. **Recurrence.** The same waste comes back next month because nothing fixed the source.
3. **Process.** Every change needs evidence, an approver and a rollback plan.

## How Warden handles it

| Resource | Warden's action | Undo | Approval |
|---|---|---|---|
| Unused EBS volume | Backup snapshot, then delete | ✅ One-click restore | Once per batch |
| Unused snapshot | Move to the AWS Recycle Bin | ✅ 7 days | Once per batch |
| Idle EC2 instance | Stop (never terminate) | ✅ Start | Once per batch |
| Unused Elastic IP | Release | ❌ Permanent | **Each item** |

**The rule:** anything reversible is approved once per batch (max 5). Anything irreversible is approved one item at a time.

## Proof before action

- Protected tags (`production`, `legal-hold`, `dr`) are never touched. The code refuses, and a shipped IAM policy makes AWS refuse too.
- Resources managed by IaC or autoscaling are skipped, because they would come back or break deploys.
- Dependency chains are checked: snapshot → AMI → launch template.
- Activity is checked from CloudWatch over a look-back window.
- The owner is looked up from CloudTrail.
- **Leak finder:** Warden identifies launch templates that leave disks behind when servers terminate, and gives the fix.
- An AWS `DryRun` confirms each action would succeed.
- **Plan lock:** actions only accept resource IDs that the scanner certified in this run.
- Suspicious tag text (prompt injection) is flagged and never obeyed.
- Every resource is re-checked right before acting.
- There's a freeze switch, a full audit log, and backups that expire after 7 days so Warden doesn't create new waste.
- A change record is generated in the Daytona sandbox from AWS receipts, including rollback steps.

## AI tools used

Claude Code (Anthropic) was used as a coding assistant. The team reviewed, tested and can explain all of the code.
