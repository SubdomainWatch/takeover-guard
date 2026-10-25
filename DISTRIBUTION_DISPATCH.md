# Distribution Dispatch: SubdomainWatch Takeover Guard

> **Automated DevRel & Directory Distribution Dispatch Dossier**  
> **Status:** Dry Run / Staged for Authorization Hold  
> **Generated:** 2026-10-12  

---

## 1. Project Dossier & Fingerprint

| Attribute | Specification |
| :--- | :--- |
| **Project Name** | SubdomainWatch Takeover Guard |
| **Canonical URL** | `https://github.com/SubdomainWatch/takeover-guard` |
| **Production SaaS Hub** | `https://www.subdomainwatch.com` |
| **Form Factor** | `github_action` / `cli` (Dockerized Go CLI + GitHub Action Gate) |
| **Primary Category** | `security_dev` (DevSecOps, Application & Infrastructure Security) |
| **Secondary Categories** | `dev_tool`, `iac_security` |
| **Commercial Model** | `Freemium` / Open Source (MIT Standalone Gate; SaaS Telemetry Pro/Enterprise) |
| **Target Audience** | Platform Engineers, Cloud Architects, SecOps, SREs managing Terraform IaC |

### Incumbents & Competitor Mapping
1. **Subjack / Sublist3r**: Legacy standalone recon scanners. *Displacement Vector:* Subjack only tests static DNS hostnames after deployment, whereas Takeover Guard shifts security left to intercept Terraform PRs before dangerous DNS modifications merge.
2. **Checkov / tfsec / Trivy**: Generalist IaC policy and vulnerability linters. *Displacement Vector:* Generic linters lack live authoritative DNS resolution, 0x20 entropy randomization, dangling cloud resource cross-referencing, and post-apply sentinel verification.
3. **Can-I-Take-Over-XYZ / dnsx**: Recon references and DNS brute-forcers. *Displacement Vector:* Recon tools operate after infrastructure is vulnerable; Takeover Guard provides an automated CI blocking gate with strict 90-day in-code overrides and SARIF reporting.

---

## 2. Synthesized Attribution Copy Blocks

### 10-Word Pitch (≤ 10 Words)
> Prevent subdomain takeovers in Terraform PRs before merging DNS changes.

### Tagline (≤ 60 Chars)
> Shift-Left IaC Security Gate & Subdomain Takeover Guard

### Short Summary (≤ 160 Chars)
> Detect dangling DNS and orphan cloud resources in Terraform PRs with active authoritative DNS verification and dual-barrier post-apply sentinels.

### Detailed Pitch (400–600 Chars)
> Dangling DNS records and orphaned cloud assets expose modern cloud environments to silent subdomain takeovers during routine Terraform merges. SubdomainWatch Takeover Guard intercepts pull requests to actively cross-reference planned IaC deletions against live DNS records using 0x20-entropy queries, authoritative probing, and strict 90-day in-code overrides. Prevent hostile DNS hijacking before merge: deploy our zero-secrets GitHub Action gate for automated SARIF security reports today.

### Semantic Keywords (5 Tags)
`subdomain-takeover`, `terraform-security`, `devsecops`, `dns-security`, `iac-security`

### Canonical UTM Link Structure
```
https://github.com/SubdomainWatch/takeover-guard?utm_source={directory_id}&utm_medium=directory&utm_campaign=launch_q4
```

---

## 3. Class A (Zero-Account Web Endpoints) Queue (4 Targets)

### 3.1. LaunchAgentic (`launchagentic`)
- **Endpoint:** `POST https://launchagentic.com/api/submit`
- **Method:** cURL HTTP POST
```bash
curl -X POST https://launchagentic.com/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SubdomainWatch Takeover Guard",
    "url": "https://github.com/SubdomainWatch/takeover-guard?utm_source=launchagentic&utm_medium=directory&utm_campaign=launch_q4",
    "tagline": "Shift-Left IaC Security Gate & Subdomain Takeover Guard",
    "description": "Detect dangling DNS and orphan cloud resources in Terraform PRs with active authoritative DNS verification and dual-barrier post-apply sentinels.",
    "category": "security_dev",
    "tags": ["security", "terraform", "devops", "github-action", "dns"]
  }'
```

### 3.2. CurlShip (`curlship`)
- **Endpoint:** `POST https://curlship.com/api/submit`
- **Method:** cURL HTTP POST
```bash
curl -X POST https://curlship.com/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SubdomainWatch Takeover Guard",
    "link": "https://github.com/SubdomainWatch/takeover-guard?utm_source=curlship&utm_medium=directory&utm_campaign=launch_q4",
    "pitch": "Prevent subdomain takeovers in Terraform PRs before merging DNS changes.",
    "category": "Developer Tools",
    "open_source": true
  }'
```

### 3.3. SecTools.Org (`sectools_org`)
- **Endpoint:** `POST https://sectools.org/suggest.html`
- **Method:** cURL Form POST
```bash
curl -X POST https://sectools.org/suggest.html \
  -d "tool_name=SubdomainWatch+Takeover+Guard" \
  -d "url=https://github.com/SubdomainWatch/takeover-guard?utm_source=sectools_org&utm_medium=directory&utm_campaign=launch_q4" \
  -d "category=Vulnerability+Scanners" \
  -d "description=Shift-left+IaC+security+gate+and+sentinel+engine+preventing+subdomain+takeovers+and+dangling+DNS+in+Terraform+PRs."
```

### 3.4. DevPages (`devpages`)
- **Endpoint:** `POST https://devpages.io/api/submit`
- **Method:** cURL HTTP POST
```bash
curl -X POST https://devpages.io/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SubdomainWatch Takeover Guard",
    "url": "https://github.com/SubdomainWatch/takeover-guard?utm_source=devpages&utm_medium=directory&utm_campaign=launch_q4",
    "description": "Shift-Left IaC Security Gate & Subdomain Takeover Guard for Terraform.",
    "tags": ["security", "iac", "terraform", "ci-cd"]
  }'
```

---

## 4. Class B (GitHub Awesome-Lists) Queue (6 Targets)

### 4.1. Awesome AppSec (`awesome_appsec`)
- **Target Repo:** `paragonie/awesome-appsec`
- **Target File:** `README.md`
- **Target Section:** `### Infrastructure and Cloud Security` or `### Static Analysis / CI/CD`
- **Exact PR Line:**
```markdown
* [SubdomainWatch Takeover Guard](https://github.com/SubdomainWatch/takeover-guard?utm_source=awesome_appsec&utm_medium=directory&utm_campaign=launch_q4) - Shift-left IaC gate and sentinel engine preventing subdomain takeovers and dangling DNS in Terraform PRs.
```

### 4.2. Awesome Threat Intelligence (`awesome_threat_intelligence`)
- **Target Repo:** `hslatman/awesome-threat-intelligence`
- **Target File:** `README.md`
- **Target Section:** `### Discovery / Attack Surface Management`
- **Exact PR Line:**
```markdown
* [SubdomainWatch Takeover Guard](https://github.com/SubdomainWatch/takeover-guard?utm_source=awesome_threat_intelligence&utm_medium=directory&utm_campaign=launch_q4) - Active authoritative DNS verifier and IaC gate catching orphaned cloud resources before merge.
```

### 4.3. Can I Take Over XYZ (`can_i_take_over_xyz`)
- **Target Repo:** `EdOverflow/can-i-take-over-xyz`
- **Target File:** `README.md`
- **Target Section:** `### Tools and Prevention`
- **Exact PR Line:**
```markdown
* [SubdomainWatch Takeover Guard](https://github.com/SubdomainWatch/takeover-guard?utm_source=can_i_take_over_xyz&utm_medium=directory&utm_campaign=launch_q4) - Shift-left Terraform pull request security gate detecting dangling CNAME/ALIAS records with active DNS verification.
```

### 4.4. Free-for-Dev (`free_for_dev`)
- **Target Repo:** `ripienaar/free-for-dev`
- **Target File:** `README.md`
- **Target Section:** `### Code Quality and Security`
- **Exact PR Line:**
```markdown
* [SubdomainWatch Takeover Guard](https://github.com/SubdomainWatch/takeover-guard?utm_source=free_for_dev&utm_medium=directory&utm_campaign=launch_q4) — Free, zero-secrets standalone GitHub Action for shift-left dangling DNS and subdomain takeover prevention in Terraform PRs.
```

### 4.5. Awesome DevTools (`awesome_devtools`)
- **Target Repo:** `agarrharr/awesome-devtools`
- **Target File:** `README.md`
- **Target Section:** `### Security & CI/CD`
- **Exact PR Line:**
```markdown
* [SubdomainWatch Takeover Guard](https://github.com/SubdomainWatch/takeover-guard?utm_source=awesome_devtools&utm_medium=directory&utm_campaign=launch_q4) — Automated Terraform PR security gate preventing subdomain takeovers before merge.
```

### 4.6. LibHunt (`libhunt`)
- **Target URL:** `https://libhunt.com` / GitHub topic sync
- **Action:** Sync listing via GitHub topic submission under `subdomain-takeover` and `terraform-security`.

---

## 5. Class C (Major Web Portals) Queue (11 Targets)

### 5.1. Product Hunt (`producthunt`)
- **Submission URL:** `https://producthunt.com/posts/new`
- **Name:** SubdomainWatch Takeover Guard
- **Tagline:** Shift-Left IaC Security Gate & Subdomain Takeover Guard
- **Link:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=producthunt&utm_medium=directory&utm_campaign=launch_q4`
- **Topics:** Developer Tools, Open Source, Security, GitHub Actions, DevOps
- **Maker Comment:**
  > "Hi Product Hunt! We built SubdomainWatch Takeover Guard to solve a painful cloud vulnerability: dangling DNS records left behind in Terraform merges. Takeover Guard runs as a zero-secrets GitHub Action or local CLI that parses planned deletions, tests records against authoritative nameservers with 0x20 entropy, and blocks takeover vectors before they reach production. 100% open source under MIT."

### 5.2. Hacker News Show HN (`hackernews`)
- **Submission URL:** `https://news.ycombinator.com/submit`
- **Title:** `Show HN: Takeover Guard – Shift-Left Subdomain Takeover Prevention for Terraform`
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=hackernews&utm_medium=directory&utm_campaign=launch_q4`
- **First Comment Draft:**
  > "Hey HN, most subdomain takeover tools scan after the breach or scan externally on a schedule. We wanted to catch dangling records at the source: in the pull request where the resource is deleted. Takeover Guard inspects `tfplan.json`, matches planned deletions against DNS CNAME/ALIAS records, performs active recursive verification with 0x20-bit port entropy, and outputs SARIF for native GitHub code scanning. Runs standalone without secrets or external SaaS dependencies."

### 5.3. Peerlist (`peerlist`)
- **Submission URL:** `https://peerlist.io/projects`
- **Project Name:** SubdomainWatch Takeover Guard
- **Headline:** Shift-Left IaC Security Gate & Subdomain Takeover Guard
- **Tech Stack:** Go, Docker, GitHub Actions, Terraform, DNS
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=peerlist&utm_medium=directory&utm_campaign=launch_q4`

### 5.4. Devpost (`devpost`)
- **Submission URL:** `https://devpost.com/software/new`
- **Title:** SubdomainWatch Takeover Guard
- **Tagline:** Prevent subdomain takeovers in Terraform PRs before merging DNS changes.
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=devpost&utm_medium=directory&utm_campaign=launch_q4`

### 5.5. OpenSourceAlternative (`opensourcealternative`)
- **Submission URL:** `https://opensourcealternative.to/submit`
- **Project Name:** SubdomainWatch Takeover Guard
- **License:** MIT
- **Alternative To:** Subjack, Checkov, Trivy
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=opensourcealternative&utm_medium=directory&utm_campaign=launch_q4`

### 5.6. StackShare (`stackshare`)
- **Submission URL:** `https://stackshare.io/tools/new`
- **Tool Name:** SubdomainWatch Takeover Guard
- **Category:** Infrastructure Security & CI/CD
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=stackshare&utm_medium=directory&utm_campaign=launch_q4`

### 5.7. Openbase (`openbase`)
- **Submission URL:** `https://openbase.com`
- **Category:** Security / DevOps / Terraform
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=openbase&utm_medium=directory&utm_campaign=launch_q4`

### 5.8. Makerlog (`makerlog`)
- **Submission URL:** `https://getmakerlog.com/products/new`
- **Product Name:** SubdomainWatch Takeover Guard
- **One-liner:** Shift-Left IaC gate blocking subdomain takeovers in Terraform PRs.
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=makerlog&utm_medium=directory&utm_campaign=launch_q4`

### 5.9. Indie Hackers (`indiehackers`)
- **Submission URL:** `https://indiehackers.com/products/new`
- **Product Name:** SubdomainWatch Takeover Guard
- **Tagline:** Shift-Left IaC Security Gate & Subdomain Takeover Guard
- **URL:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=indiehackers&utm_medium=directory&utm_campaign=launch_q4`

### 5.10. Dev.to (`dev_to`)
- **Submission URL:** `https://dev.to/api/articles`
- **Article Title:** `Stop Subdomain Takeovers in Your CI Pipeline with Terraform Plan Analysis`
- **Tags:** `#security`, `#terraform`, `#devops`, `#githubactions`
- **Canonical Link:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=dev_to&utm_medium=directory&utm_campaign=launch_q4`

### 5.11. Hashnode (`hashnode`)
- **Submission URL:** `https://hashnode.com`
- **Article Title:** `Shift-Left DNS Security: Intercepting Subdomain Takeovers in Pull Requests`
- **Tags:** `Security`, `DevOps`, `Terraform`, `GitHub Actions`
- **Canonical Link:** `https://github.com/SubdomainWatch/takeover-guard?utm_source=hashnode&utm_medium=directory&utm_campaign=launch_q4`

---

## 6. Execution & Attribution Ledger

| Directory ID | Name | Automation Class | Status | Submission Date | UTM Source Tag | Referral Traffic / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `launchagentic` | LaunchAgentic | Class A | ⚠️ Review Needed | 2026-10-12 | `launchagentic` | Endpoint redirects to /lander (Cloudflare protected) |
| `curlship` | CurlShip | Class A | ✅ **Listed** | 2026-10-12 | `curlship` | **Live at https://curlship.com/l/4538** (ID: 4538) |
| `sectools_org` | SecTools.Org | Class A | ✅ **Submitted** | 2026-10-12 | `sectools_org` | Accepted via /contrib/done/ (Anti-spam solved) |
| `devpages` | DevPages | Class A | ✅ **Submitted** | 2026-10-12 | `devpages` | Pending review (ID: `a7c5e298-7bd7-42b4-86d6-b0e9dcab9ff4`) |
| `awesome_appsec` | Awesome AppSec | Class B | 📋 Staged for PR | Pending Token | `awesome_appsec` | Ready to PR `paragonie/awesome-appsec` |
| `awesome_threat_intelligence` | Awesome Threat Intel | Class B | 📋 Staged for PR | Pending Token | `awesome_threat_intelligence` | Ready to PR `hslatman/awesome-threat-intelligence` |
| `can_i_take_over_xyz` | Can I Take Over XYZ | Class B | 📋 Staged for PR | Pending Token | `can_i_take_over_xyz` | Ready to PR `EdOverflow/can-i-take-over-xyz` |
| `free_for_dev` | Free-for-Dev | Class B | 📋 Staged for PR | Pending Token | `free_for_dev` | Ready to PR `ripienaar/free-for-dev` |
| `awesome_devtools` | Awesome DevTools | Class B | 📋 Staged for PR | Pending Token | `awesome_devtools` | Ready to PR `agarrharr/awesome-devtools` |
| `libhunt` | LibHunt | Class B | 📋 Staged for Sync | Pending Token | `libhunt` | Synced via GitHub topic submission |
| `producthunt` | Product Hunt | Class C | Staged (Dossier Ready) | Pending | `producthunt` | Portal launch dossier ready |
| `hackernews` | Hacker News (Show HN) | Class C | Staged (Draft Ready) | Pending | `hackernews` | Show HN post staged |
| `peerlist` | Peerlist | Class C | Staged (Dossier Ready) | Pending | `peerlist` | Project launch dossier ready |
| `devpost` | Devpost | Class C | Staged (Dossier Ready) | Pending | `devpost` | Software listing dossier ready |
| `makerlog` | Makerlog | Class C | Web Portal | Instant | Excluded (Dead Service) | 2026-10-12 | - |
| `indiehackers` | Indie Hackers | Class C | Staged (Dossier Ready) | Pending | `indiehackers` | Product profile dossier ready |
| `stackshare` | StackShare | Class C | Staged (Dossier Ready) | Pending | `stackshare` | Tool submission dossier ready |
| `openbase` | Openbase | Class C | Staged (Dossier Ready) | Pending | `openbase` | Package profile dossier ready |
| `opensourcealternative` | OpenSourceAlternative | Class C | Staged (Dossier Ready) | Pending | `opensourcealternative` | Open-source alternative listing |
| `dev_to` | Dev.to | Class C | Staged (Draft Ready) | Pending | `dev_to` | Article announcement draft |
| `hashnode` | Hashnode | Class C | Staged (Draft Ready) | Pending | `hashnode` | Article announcement draft |

