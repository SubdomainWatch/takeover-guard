# SubdomainWatch Takeover Guard
> **Shift-Left IaC Security Gate & Post-Apply Sentinel Engine**  
> Prevent subdomain takeovers before merge. Detect dangling DNS and orphan cloud resources in Terraform PRs with active authoritative verification.

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Marketplace-red?logo=github)](https://github.com/marketplace/actions/subdomainwatch-takeover-guard)
[![Release: v2.3.0](https://img.shields.io/badge/release-v2.3.0-blue.svg)](https://github.com/SubdomainWatch/takeover-guard/releases/tag/v2.3.0)
[![Docker: v2.3.0](https://img.shields.io/badge/docker-v2.3.0-blue?logo=docker)](https://github.com/SubdomainWatch/takeover-guard/pkgs/container/takeover-guard)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-blue)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)

---

## 1. Quickstart (GitHub Actions)

Add this minimal workflow to your repository at `.github/workflows/takeover-guard.yml`:

```yaml
name: Subdomain Takeover Prevention Gate

on:
  pull_request:
    paths:
      - '**.tf'
      - '**.tfplan'
      - '**/dns/**'

permissions:
  contents: read

jobs:
  guard-check:
    name: Subdomain Takeover Prevention Gate
    runs-on: ubuntu-latest
    timeout-minutes: 3
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Takeover Guard
        uses: SubdomainWatch/takeover-guard@v2
        with:
          tf_dir: '.'                  # Default: Zero-credential static HCL scan of local .tf files
          # plan_file: ''              # Optional: Defaults to static HCL scan; provide path (e.g. 'tfplan.json') for plan scanning
          fail_on_severity: 'CRITICAL'
          fail_mode: 'closed'
          sarif_file: 'takeover-guard.sarif'
```

> [!TIP]
> **Zero-Credential Static Scanning:** `plan_file: ''` is optional and defaults to zero-credential static HCL scanning across the workspace directory specified by `tf_dir: '.'` (no `terraform init`, cloud provider credentials, or generated plan file required).
> If you wish to scan a speculative Terraform plan instead, generate `tfplan.json` in a preceding workflow step and specify `plan_file: 'tfplan.json'`.

> [!CAUTION]
> **Fork PR Security Invariant (P0-3):**  
> **NEVER use `pull_request_target` with SubdomainWatch Takeover Guard.**  
> Workflows triggered by `on: pull_request_target` grant untrusted code from fork pull requests write access and exposure to repository secrets. Always use `on: pull_request` to run in an unprivileged, read-only runner sandbox.

---

## 2. CLI, Local & Pre-Commit Usage

Takeover Guard can be executed locally as a standalone CLI binary, via Docker container, or as a Git `pre-commit` hook.

### A. Zero-Credential Static HCL Workspace Scanning (`--tf-dir`)
Scan Terraform configuration directly without requiring `terraform init`, cloud provider credentials, or a generated plan file. Takeover Guard statically inspects DNS and storage definitions across:
* **AWS**: Route53 (`aws_route53_record` - CNAME & ALIAS) & S3 (`aws_s3_bucket`)
* **Cloudflare**: DNS records (`cloudflare_record`)
* **Azure DNS**: CNAME & A records (`azurerm_dns_cname_record`, `azurerm_dns_a_record`)
* **Google Cloud DNS**: Resource record sets (`google_dns_record_set`)

```bash
# Scan current directory (.tf files)
subdomainwatch-guard --tf-dir .

# Via Docker (rootless container)
docker run --rm -v $(pwd):/workspace ghcr.io/subdomainwatch/takeover-guard:v2.3.0 --tf-dir /workspace
```

### B. Terraform Plan JSON Scanning (`--plan-file` / `--plan`)
Scan speculative changes in CI or local development from a Terraform plan file:

```bash
# Generate plan JSON (traditional CI pipeline)
terraform init -backend=false || true
terraform plan -out=tfplan.binary || true
terraform show -json tfplan.binary > tfplan.json

# Scan plan file (--plan and --plan-file aliases supported)
subdomainwatch-guard --plan tfplan.json
# or: subdomainwatch-guard --plan-file tfplan.json

# Via Docker
docker run --rm -v $(pwd):/workspace ghcr.io/subdomainwatch/takeover-guard:v2.3.0 --plan /workspace/tfplan.json
```

### C. Pre-Commit Hook Integration
Add Takeover Guard to your `.pre-commit-config.yaml` to prevent committing dangling DNS records:

```yaml
repos:
  - repo: https://github.com/SubdomainWatch/takeover-guard
    rev: v2.3.0
    hooks:
      - id: takeover-guard
        args:
          - "-fail-on-severity"
          - "CRITICAL"
          - "-fail-mode"
          - "closed"
```

---

## 3. Dual-Barrier Detection Architecture

SubdomainWatch Takeover Guard operates a two-tier barrier to eliminate dangling DNS records across the entire deployment lifecycle:

| Barrier | Trigger | Execution Mode | What It Catches |
| :--- | :--- | :--- | :--- |
| **Barrier 1: Pre-Merge Gate** | `on: pull_request` | `mode: pre-merge` | Planned resource deletions (S3 buckets, Heroku apps, GitHub Pages) where DNS CNAME/ALIAS records remain in code. |
| **Barrier 2: Post-Apply Sentinel** | `on: push` to `main` | `mode: post-apply-sentinel` | Out-of-band deletions, cross-state resource removals, manual cloud console changes, and dynamic computed records after `terraform apply`. |

### DNS Resolution Architecture Note (P2-6)
The Sentinel engine queries DNS recursors (`1.1.1.1`, `8.8.8.8`) with randomized 0x20 bit entropy and randomized ports, paired with an enforced **45-second settle delay** (`settle_delay: 45`) to mitigate intermediate DNS TTL caching. Authoritative NS traversal is handled directly by the prober engine.

---

## 4. Strict In-Code Override Protocol

To accept a known risk (e.g. an ephemeral staging preview or CDN vanity hostname) without breaking CI builds, add a `# subdomainwatch-ignore:` or `// subdomainwatch-ignore:` comment directly above the resource block:

```hcl
# Line N-1 Proximity Binding: Must be placed directly above the resource
# subdomainwatch-ignore: SW-G-001 domain=staging.acme.com expires=2026-12-31 approver=@sec-ops reason="Ephemeral preview hash router"
resource "aws_route53_record" "staging" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "staging.acme.com"
  type    = "CNAME"
  ttl     = 300
  records = ["unclaimed-preview.herokuapp.com"]
}
```

### Compliance Guardrails
* **Line-Proximity Binding:** The comment must be on line `N-1` (or `N-2` allowing at most 1 blank line) directly preceding `resource`. Detached or file-header comments are rejected.
* **Exact FQDN Binding:** The `domain=` attribute must match the resource's DNS name.
* **Explicit Rule IDs (P1-1):** Blanket wildcard `*` rule IDs are **prohibited**. You must explicitly declare the rule being bypassed (e.g. `SW-G-001` or `SW-G-002`).
* **Maximum 90-Day Policy:** Expiration dates exceeding 90 days are rejected by the parser.
* **Graceful Expiration Degradation (P1-4):** When an override expires (`expires <= today`), it emits a visible warning to stderr and stops suppressing findings, allowing findings to trigger without crashing unrelated PRs.
* **Comment Styles Supported (P1-2):** Both `#` and `//` comment styles are supported.

---

## 5. Freemium vs. Enterprise SaaS Sync

SubdomainWatch Takeover Guard is designed as an open-core developer security tool:

### Free Standalone Mode (£0 / No Account)
* **Zero secrets required.**
* Runs locally in your GitHub Actions runner or workstation.
* Parses static HCL or plan JSON, evaluates overrides, tests cloud signatures, and outputs SARIF reports directly into GitHub's **Security → Code scanning** tab.
* No data leaves your runner.

### Enterprise SaaS Sync (SubdomainWatch Pro / Enterprise)
* To centralize PR compliance across all engineering repositories:
  1. Generate an API Key in SubdomainWatch Console at [`https://www.subdomainwatch.com/console/guard`](https://www.subdomainwatch.com/console/guard).
  2. Add `SUBDOMAINWATCH_API_KEY: ${{ secrets.SUBDOMAINWATCH_API_KEY }}` to your GitHub repository secrets.
  3. All PR results, override logs, and branch drift automatically populate the central CISO telemetry hub.

---

## 6. Release & GHCR Operational Checklist

When releasing new versions to the GitHub Actions Marketplace:

1. **Tag & Push Git Release:**
   ```bash
   git tag -a v2.2.0 -m "Release Takeover Guard v2.2.0 — Zero-Credential Static HCL Engine & SSRF Hardening"
   git tag -fa v2 -m "Update v2 rolling pointer"
   git push origin main
   git push origin v2.2.0 --force
   git push origin v2 --force
   ```
2. **GHCR Container Build:**
   * GitHub Actions runs `.github/workflows/release.yml` to compile multi-arch binaries (`linux/amd64`, `linux/arm64`) and publish images to `ghcr.io/subdomainwatch/takeover-guard:v2.2.0` and `ghcr.io/subdomainwatch/takeover-guard:v2`.
3. **Configure GHCR Package Permissions (One-Time Setup):**
   * Navigate to `https://github.com/orgs/SubdomainWatch/packages/container/takeover-guard/settings` (or your org package settings).
   * Set visibility to **Public** so external workflows can pull without authentication.
   * Under **"Manage Actions access"**, verify the repository `SubdomainWatch/takeover-guard` has the **Write** role.
4. **Publish to Marketplace:**
   * Open the GitHub Releases page for tag `v2.2.0`.
   * Select **"Publish this Action to the GitHub Marketplace"**.
   * Ensure Primary category is **Security** and Secondary category is **Continuous Integration**.
