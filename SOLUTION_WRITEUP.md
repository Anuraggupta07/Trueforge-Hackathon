# Warden: solution write-up

**Warden is cloud cleanup that proves it's safe first.** It is an AI agent built on TrueForge for *Agents That Act* (TrueFoundry × Polaris, 26 September 2026).

## The problem
About 29% of cloud spend is wasted (Flexera 2026). Finding idle resources is easy. Deleting them safely is not: a cleanup script given the wrong IDs deleted 883 Atlassian customer sites. Teams stall on fear, recurring waste and change paperwork.

## What the agent reaches
Through our Python MCP server (boto3), the agent reaches:
- AWS **EC2**: volumes, snapshots, instances and Elastic IPs
- **CloudWatch**, **CloudTrail**, the **Recycle Bin**, **Route 53** and **ELBv2**
- A **Daytona sandbox**, where it runs Warden's proof script to recompute the savings independently

## Where it stops
- It refuses production, legal-hold and IaC/autoscaling resources, anything an image, DNS record or load balancer still uses, and prompt-injection text in tags.
- Every change needs an independent Watchdog's single-use, HMAC-signed sign-off **and** a human Allow in TrueForge.
- Permanent steps (IP release) come only after a quarantine window, and need their own approval.
- It never terminates instances, never touches KMS keys and never deletes S3 buckets.

## Architecture
The flow is TrueForge chat → Warden MCP server → AWS. Inside the server:
- **Scanner:** builds a locked plan.
- **Watchdog:** re-checks and signs.
- **Executor:** the only code that mutates AWS.
- **Ledger:** hash-chained.

A read-only Warden Console shows live state and undo countdowns. Actions are reversible first: backups, the Recycle Bin, stop instead of terminate.

## How TrueForge was used
- A custom MCP connector (19 tools) with approval on all 10 action tools
- The Daytona sandbox
- Generative-UI dashboards
- The agent defined in code with the SDK
- A model through the TrueFoundry AI Gateway
- Sessions

## Real versus mocked
TrueForge, the AI Gateway model, the Daytona sandbox and all of Warden's code are real. Our AWS account never activated (`OptInRequired`), so the demo uses **moto**, a local AWS simulator, and the screen says so. Switching to real AWS is one line in `.env`.

## Known limits
- One region and one account per run
- Four resource types
- Idle means "quiet in the look-back window"
- List-price savings estimates
- A tamper-evident, not tamper-proof, ledger

The repo has 491 automated tests and an MIT licence.
