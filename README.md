# vertex-iam-audit

A command-line security auditor for **GCP Vertex AI IAM policies and service accounts**. It scans a project for misconfigurations that could expose Vertex AI resources to unauthorized access and produces a colour-coded terminal report plus an optional JSON export.

---

## Table of Contents

- [Why this tool](#why-this-tool)
- [Security checks](#security-checks)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Authentication](#authentication)
- [Usage](#usage)
- [Output & exit codes](#output--exit-codes)
- [Integrating into CI/CD](#integrating-into-cicd)
- [Required IAM permissions](#required-iam-permissions)
- [Findings reference](#findings-reference)

---

## Why this tool

Vertex AI workloads often run under service accounts with broad permissions inherited from primitive roles (`roles/owner`, `roles/editor`). Keys for those service accounts accumulate over time and are rarely rotated. Wildcard principals (`allUsers`, `allAuthenticatedUsers`) occasionally appear after quick-fix demos and never get cleaned up.

This tool makes those problems visible in under a minute, without requiring any third-party security platform.

---

## Security checks

| Check ID | Severity | What is flagged |
|---|---|---|
| `wildcard_principal_vertex_role` | HIGH / MEDIUM | `allUsers` or `allAuthenticatedUsers` bound to any Vertex AI or ML role |
| `primitive_role_on_service_account` | MEDIUM | A service account holds `roles/owner` or `roles/editor` |
| `vertex_admin_role_on_user` | LOW | A human user directly holds a Vertex AI admin role |
| `stale_service_account_key` | HIGH / MEDIUM | User-managed SA key older than 180 days (HIGH) or 90 days (MEDIUM) |
| `multiple_sa_keys` | MEDIUM | Service account has more than one active user-managed key |
| `wildcard_sa_impersonation` | HIGH | `allUsers` / `allAuthenticatedUsers` can impersonate a service account |
| `user_can_impersonate_sa` | LOW | A human user can directly impersonate a service account |

---

## Prerequisites

- Python 3.10+
- A GCP project ID
- `gcloud` CLI (for application-default credentials) **or** a service account key file
- The auditor identity must have [the required IAM permissions](#required-iam-permissions)

---

## Installation

```bash
git clone https://github.com/tyler-coady/vertex-iam-audit.git
cd vertex-iam-audit
pip install -r requirements.txt
```

Prefer an isolated environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Authentication

The tool uses [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials). Pick one method:

**Interactive (developer workstation)**

```bash
gcloud auth application-default login
```

**Service account key file**

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
```

**Workload Identity / Cloud Run / GCE**  
ADC is picked up automatically — no additional configuration needed.

---

## Usage

```
python vertex_iam_auditor.py --project PROJECT_ID [--output FILE] [--severity LEVEL]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--project` | Yes | — | GCP project ID to audit |
| `--output` | No | — | Write findings to a JSON file at this path |
| `--severity` | No | `LOW` | Minimum severity to display: `HIGH`, `MEDIUM`, `LOW`, or `INFO` |

### Examples

Audit a project and show all findings down to LOW severity:

```bash
python vertex_iam_auditor.py --project my-gcp-project
```

Show only HIGH and MEDIUM findings:

```bash
python vertex_iam_auditor.py --project my-gcp-project --severity MEDIUM
```

Save findings to a JSON file for downstream processing or ticketing:

```bash
python vertex_iam_auditor.py --project my-gcp-project --output findings.json
```

Combine flags:

```bash
python vertex_iam_auditor.py \
  --project my-gcp-project \
  --severity MEDIUM \
  --output findings.json
```

---

## Output & exit codes

### Terminal output

The tool prints a colour-coded finding list:

```
  [1] [HIGH]  wildcard_principal_vertex_role
      Resource       : projects/my-gcp-project → roles/aiplatform.admin
      Detail         : Principal 'allUsers' has role 'roles/aiplatform.admin'. ...
      Recommendation : Remove the wildcard principal immediately. ...
```

Summary line:

```
  Project : my-gcp-project
  Scanned : 2026-05-02T20:00:00+00:00
  Totals  : HIGH=1 MEDIUM=2 LOW=0 INFO=0
```

### JSON output (`--output`)

```json
{
  "project_id": "my-gcp-project",
  "scanned_at": "2026-05-02T20:00:00+00:00",
  "summary": { "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 0 },
  "findings": [
    {
      "severity": "HIGH",
      "check": "wildcard_principal_vertex_role",
      "resource": "projects/my-gcp-project → roles/aiplatform.admin",
      "detail": "...",
      "recommendation": "..."
    }
  ]
}
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings (or all findings below the selected severity) |
| `1` | At least one MEDIUM finding, no HIGH |
| `2` | At least one HIGH finding |

Use these in CI pipelines to gate deployments or trigger alerts.

---

## Integrating into CI/CD

### GitHub Actions

```yaml
name: Vertex AI IAM Audit

on:
  schedule:
    - cron: "0 6 * * 1"   # every Monday at 06:00 UTC
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # for Workload Identity Federation

    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WIF_PROVIDER }}
          service_account: ${{ secrets.AUDIT_SA_EMAIL }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run audit
        run: |
          python vertex_iam_auditor.py \
            --project ${{ secrets.GCP_PROJECT_ID }} \
            --severity MEDIUM \
            --output findings.json

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: iam-audit-findings
          path: findings.json
```

The workflow exits with a non-zero code if MEDIUM or HIGH findings are present, which will fail the GitHub Actions run.

---

## Required IAM permissions

The identity running the auditor needs these roles (or their individual permissions):

| Role | Why it is needed |
|---|---|
| `roles/resourcemanager.projectIamViewer` | Read project-level IAM policy |
| `roles/iam.serviceAccountViewer` | List service accounts |
| `roles/iam.serviceAccountKeyAdmin` *(viewer subset)* | List service account keys |

For a least-privilege custom role, bind these permissions:

```
resourcemanager.projects.getIamPolicy
iam.serviceAccounts.list
iam.serviceAccountKeys.list
iam.serviceAccounts.getIamPolicy
```

---

## Findings reference

### `wildcard_principal_vertex_role`
**Severity:** HIGH (admin roles) / MEDIUM (viewer/user roles)

`allUsers` or `allAuthenticatedUsers` appears in a binding that grants any Vertex AI or ML role. This exposes model endpoints, training jobs, or pipelines to the entire internet or all Google-authenticated accounts. Remove the wildcard and replace it with a specific service account or group.

---

### `primitive_role_on_service_account`
**Severity:** MEDIUM

`roles/owner` or `roles/editor` grants full Vertex AI access as a side-effect of general project access. These primitive roles bypass the principle of least privilege. Replace with specific Vertex AI roles scoped to the resources the SA actually needs.

---

### `vertex_admin_role_on_user`
**Severity:** LOW

A personal Google account holds a Vertex AI admin role directly on the project. Personal accounts are higher-risk than service accounts (phishing, MFA gaps). Move the binding to a Google Group and enforce MFA for all members.

---

### `stale_service_account_key`
**Severity:** HIGH (> 180 days) / MEDIUM (> 90 days)

Long-lived user-managed keys are the most common cause of credential theft in GCP environments. Rotate keys before the 90-day mark, and prefer [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) to eliminate key files entirely.

---

### `multiple_sa_keys`
**Severity:** MEDIUM

Each active key is an independent secret that can be exfiltrated and used independently. Maintain at most one key per service account, and only during a rotation window. Ideally: zero keys (use Workload Identity).

---

### `wildcard_sa_impersonation`
**Severity:** HIGH

A wildcard principal can generate tokens for this service account, inheriting all of its permissions. This is effectively the same as making the service account public. Remove the wildcard from the SA's IAM policy immediately.

---

### `user_can_impersonate_sa`
**Severity:** LOW

A personal user account has a role that allows generating short-lived tokens for this service account (`iam.serviceAccountTokenCreator`, `iam.workloadIdentityUser`, etc.). Impersonation rights should be granted to groups or other service accounts, not individuals, to reduce the blast radius of a compromised personal account.
