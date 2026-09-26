# Sweep: approval-gated cloud cost cleanup

Sweep is an AI agent built on [TrueForge](https://github.com/truefoundry/trueforge). It finds wasted spend in a real AWS account, proves what a cleanup would do, and deletes **only after a human approves**, taking a backup snapshot first.

Built for **Agents That Act**, a TrueFoundry × Polaris hackathon (26 September 2026).

> 🚧 Work in progress. Setup and run instructions will be added as the build lands.

## How it works

1. **Find:** scans AWS through our MCP server for idle resources (unattached disks, idle IPs, old snapshots, idle servers) and their monthly cost.
2. **Prove:** runs a dry-run analysis in a Daytona sandbox that shows exactly what would change.
3. **Ask:** grades the risk of each item and pauses on an approval card. Nothing is deleted without a human clicking Approve.
4. **Act:** takes a backup snapshot, deletes, confirms and reports the savings.

## Safety rules

- Dry run by default.
- Never touches anything tagged `production`.
- Caps the number of deletions per run.
- Takes a backup before every delete.
- Logs every action.

## AI tools used

Claude Code (Anthropic) was used as a coding assistant. The team reviewed, tested and can explain all of the code.
