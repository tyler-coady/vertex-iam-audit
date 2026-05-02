#!/usr/bin/env python3
"""
vertex_iam_auditor.py
---------------------
GCP Vertex AI IAM & Service Account Security Auditor

Scans your GCP project for IAM and service account misconfigurations
that could expose Vertex AI resources to unauthorized access.

Usage:
    python vertex_iam_auditor.py --project YOUR_PROJECT_ID
    python vertex_iam_auditor.py --project YOUR_PROJECT_ID --output report.json
    python vertex_iam_auditor.py --project YOUR_PROJECT_ID --severity HIGH

Prerequisites:
    pip install google-cloud-iam google-cloud-resource-manager google-auth

Authentication:
    gcloud auth application-default login
    -- or --
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ── Colour helpers (no external deps) ────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
DIM    = "\033[2m"


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"


# ── Data models ───────────────────────────────────────────────────────────────
@dataclass
class Finding:
    severity: str          # HIGH | MEDIUM | LOW | INFO
    check: str             # short check name
    resource: str          # affected resource
    detail: str            # human-readable explanation
    recommendation: str    # what to do

    def severity_colour(self) -> str:
        return {
            "HIGH":   RED,
            "MEDIUM": YELLOW,
            "LOW":    CYAN,
            "INFO":   DIM,
        }.get(self.severity, RESET)


@dataclass
class AuditReport:
    project_id: str
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ── Risk constants ────────────────────────────────────────────────────────────
# Roles that give broad Vertex AI / ML access
VERTEX_ADMIN_ROLES = {
    "roles/aiplatform.admin",
    "roles/ml.admin",
    "roles/owner",
    "roles/editor",
}

# Roles with read/predict access (lower risk but worth flagging on allUsers)
VERTEX_SENSITIVE_ROLES = {
    "roles/aiplatform.user",
    "roles/aiplatform.viewer",
    "roles/ml.developer",
    "roles/ml.viewer",
}

# Catch-all wildcards
WILDCARD_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}

# Service account roles that allow impersonation / key creation
SA_DANGEROUS_ROLES = {
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.workloadIdentityUser",
}


# ── Audit functions ───────────────────────────────────────────────────────────

def audit_project_iam(report: AuditReport, crm_client, iam_client) -> None:
    """Check project-level IAM bindings for Vertex AI risk."""
    print(c("  → Fetching project IAM policy …", DIM))

    try:
        policy = crm_client.get_iam_policy(
            request={"resource": f"projects/{report.project_id}"}
        )
    except Exception as exc:
        report.add(Finding(
            severity="INFO",
            check="iam_policy_fetch",
            resource=f"projects/{report.project_id}",
            detail=f"Could not retrieve IAM policy: {exc}",
            recommendation="Ensure the auditor has roles/resourcemanager.projectIamAdmin or viewer.",
        ))
        return

    for binding in policy.bindings:
        role    = binding.role
        members = list(binding.members)

        # 1. Wildcard principals on any Vertex / ML role
        for principal in members:
            if principal in WILDCARD_PRINCIPALS:
                sev = "HIGH" if role in VERTEX_ADMIN_ROLES else "MEDIUM"
                if role in VERTEX_ADMIN_ROLES | VERTEX_SENSITIVE_ROLES or "aiplatform" in role or "ml." in role:
                    report.add(Finding(
                        severity=sev,
                        check="wildcard_principal_vertex_role",
                        resource=f"projects/{report.project_id} → {role}",
                        detail=(
                            f"Principal '{principal}' has role '{role}'. "
                            "This grants Vertex AI access to everyone on the internet "
                            "(allUsers) or all authenticated Google accounts (allAuthenticatedUsers)."
                        ),
                        recommendation=(
                            "Remove the wildcard principal immediately. "
                            "Grant access only to specific service accounts or user groups."
                        ),
                    ))

        # 2. Primitive owner/editor roles (project-wide blast radius)
        if role in ("roles/owner", "roles/editor"):
            # Only flag if many members or service accounts hold it
            sa_members = [m for m in members if m.startswith("serviceAccount:")]
            if sa_members:
                report.add(Finding(
                    severity="MEDIUM",
                    check="primitive_role_on_service_account",
                    resource=f"projects/{report.project_id} → {role}",
                    detail=(
                        f"Service account(s) {sa_members} hold the primitive '{role}' role, "
                        "which includes full Vertex AI access alongside all other GCP services."
                    ),
                    recommendation=(
                        "Replace with fine-grained roles such as roles/aiplatform.user "
                        "or roles/aiplatform.admin scoped to specific resources."
                    ),
                ))

        # 3. Direct Vertex admin roles on external (non-SA) identities
        if role in VERTEX_ADMIN_ROLES:
            user_members = [m for m in members if m.startswith("user:")]
            if user_members:
                report.add(Finding(
                    severity="LOW",
                    check="vertex_admin_role_on_user",
                    resource=f"projects/{report.project_id} → {role}",
                    detail=(
                        f"Human user(s) {user_members} hold '{role}' directly on the project. "
                        "Personal accounts increase risk from credential theft or account takeover."
                    ),
                    recommendation=(
                        "Prefer granting admin roles to groups rather than individual users. "
                        "Enable MFA and review whether admin access is still needed."
                    ),
                ))


def audit_service_accounts(report: AuditReport, iam_client) -> None:
    """Check service accounts for key age, excessive roles, and dangerous permissions."""
    print(c("  → Enumerating service accounts …", DIM))

    try:
        sa_list = list(iam_client.list_service_accounts(
            name=f"projects/{report.project_id}"
        ))
    except Exception as exc:
        report.add(Finding(
            severity="INFO",
            check="service_account_list",
            resource=f"projects/{report.project_id}",
            detail=f"Could not list service accounts: {exc}",
            recommendation="Grant roles/iam.serviceAccountViewer to the auditor.",
        ))
        return

    print(c(f"  → Found {len(sa_list)} service account(s). Inspecting keys …", DIM))

    for sa in sa_list:
        sa_email = sa.email
        _audit_sa_keys(report, iam_client, sa_email)
        _audit_sa_iam_policy(report, iam_client, sa_email)


def _audit_sa_keys(report: AuditReport, iam_client, sa_email: str) -> None:
    """Flag user-managed keys older than 90 days."""
    try:
        keys_response = iam_client.list_service_account_keys(
            name=f"projects/{report.project_id}/serviceAccounts/{sa_email}"
        )
        keys = [k for k in keys_response.keys
                if k.key_type.name == "USER_MANAGED"]
    except Exception:
        return  # Skip silently; permissions issue surfaced at list stage

    now = datetime.now(timezone.utc)

    for key in keys:
        if not key.valid_after_time:
            continue
        age_days = (now - key.valid_after_time).days

        if age_days > 180:
            sev = "HIGH"
            label = "stale (>180 days)"
        elif age_days > 90:
            sev = "MEDIUM"
            label = "aging (>90 days)"
        else:
            continue

        report.add(Finding(
            severity=sev,
            check="stale_service_account_key",
            resource=sa_email,
            detail=(
                f"User-managed key '{key.name.split('/')[-1]}' is {label} "
                f"(created {age_days} days ago). Long-lived keys are high-value targets."
            ),
            recommendation=(
                "Rotate or delete this key. Prefer Workload Identity Federation "
                "to eliminate long-lived key files entirely."
            ),
        ))

    if len(keys) > 1:
        report.add(Finding(
            severity="MEDIUM",
            check="multiple_sa_keys",
            resource=sa_email,
            detail=(
                f"Service account has {len(keys)} active user-managed key(s). "
                "Each additional key expands the blast radius if one is compromised."
            ),
            recommendation=(
                "Reduce to a single key per service account, "
                "or migrate to keyless authentication via Workload Identity."
            ),
        ))


def _audit_sa_iam_policy(report: AuditReport, iam_client, sa_email: str) -> None:
    """Check who can act-as this service account (impersonation risk)."""
    try:
        policy = iam_client.get_iam_policy(
            request={"resource": f"projects/{report.project_id}/serviceAccounts/{sa_email}"}
        )
    except Exception:
        return

    for binding in policy.bindings:
        role    = binding.role
        members = list(binding.members)

        if role not in SA_DANGEROUS_ROLES:
            continue

        for principal in members:
            if principal in WILDCARD_PRINCIPALS:
                report.add(Finding(
                    severity="HIGH",
                    check="wildcard_sa_impersonation",
                    resource=sa_email,
                    detail=(
                        f"'{principal}' has '{role}' on this service account. "
                        "Anyone can impersonate it and inherit its Vertex AI permissions."
                    ),
                    recommendation=(
                        "Remove the wildcard immediately. Only specific identities "
                        "should be able to impersonate service accounts."
                    ),
                ))
            elif principal.startswith("user:"):
                report.add(Finding(
                    severity="LOW",
                    check="user_can_impersonate_sa",
                    resource=sa_email,
                    detail=(
                        f"User '{principal}' has '{role}', allowing direct impersonation "
                        "of this service account."
                    ),
                    recommendation=(
                        "Prefer granting impersonation rights to groups or other service accounts, "
                        "and audit whether this access is still required."
                    ),
                ))


# ── Output helpers ─────────────────────────────────────────────────────────────

def print_banner() -> None:
    print()
    print(c("╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("║   Vertex AI IAM & Service Account Security Auditor  ║", CYAN))
    print(c("╚══════════════════════════════════════════════════════╝", CYAN))
    print()


def print_report(report: AuditReport, min_severity: str) -> None:
    order = ["HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = order.index(min_severity) if min_severity in order else 0
    visible = [f for f in report.findings if order.index(f.severity) <= min_idx]

    counts = report.counts()
    print()
    print(c(f"{'─'*54}", DIM))
    print(c(f"  Project : {report.project_id}", BOLD))
    print(c(f"  Scanned : {report.scanned_at}", DIM))
    print(c(f"  Totals  : ", BOLD) +
          c(f"HIGH={counts['HIGH']} ", RED) +
          c(f"MEDIUM={counts['MEDIUM']} ", YELLOW) +
          c(f"LOW={counts['LOW']} ", CYAN) +
          c(f"INFO={counts['INFO']}", DIM))
    print(c(f"{'─'*54}", DIM))
    print()

    if not visible:
        print(c("  ✓  No findings at or above the selected severity.", GREEN))
        return

    for idx, f in enumerate(visible, 1):
        col = f.severity_colour()
        print(c(f"  [{idx}] ", BOLD) + c(f"[{f.severity}]", col) + f"  {f.check}")
        print(f"      Resource       : {f.resource}")
        print(f"      Detail         : {f.detail}")
        print(c(f"      Recommendation : {f.recommendation}", GREEN))
        print()


def save_json(report: AuditReport, path: str) -> None:
    data = {
        "project_id": report.project_id,
        "scanned_at": report.scanned_at,
        "summary": report.counts(),
        "findings": [asdict(f) for f in report.findings],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(c(f"  ✓  Report saved → {path}", GREEN))


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit GCP Vertex AI IAM & Service Account security.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--project",  required=True, help="GCP project ID to audit")
    p.add_argument("--output",   default=None,  help="Save findings to a JSON file")
    p.add_argument(
        "--severity",
        default="LOW",
        choices=["HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity level to display (default: LOW)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    print_banner()

    # ── Import GCP clients (deferred so the script gives a clean error) ──────
    try:
        from google.cloud import iam_admin_v1
        from google.cloud import resourcemanager_v3
    except ImportError:
        print(c("  ERROR: GCP libraries not found. Install with:", RED))
        print("         pip install google-cloud-iam google-cloud-resource-manager")
        sys.exit(1)

    report = AuditReport(project_id=args.project)

    print(c(f"  Auditing project: {args.project}\n", BOLD))

    # ── Initialise clients ───────────────────────────────────────────────────
    try:
        crm_client = resourcemanager_v3.ProjectsClient()
        iam_client = iam_admin_v1.IAMClient()
    except Exception as exc:
        print(c(f"  ERROR: Could not initialise GCP clients: {exc}", RED))
        sys.exit(1)

    # ── Run checks ───────────────────────────────────────────────────────────
    print(c("  [1/2] IAM Policy Bindings", BOLD))
    audit_project_iam(report, crm_client, iam_client)

    print(c("\n  [2/2] Service Accounts & Keys", BOLD))
    audit_service_accounts(report, iam_client)

    # ── Display results ──────────────────────────────────────────────────────
    print_report(report, args.severity)

    # ── Optionally persist ───────────────────────────────────────────────────
    if args.output:
        save_json(report, args.output)

    # Exit code reflects highest severity found
    counts = report.counts()
    if counts["HIGH"]:
        sys.exit(2)
    if counts["MEDIUM"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
