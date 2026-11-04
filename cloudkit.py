#!/usr/bin/env python3
"""Local, read-only helpers for everyday cloud configuration reviews."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    suggestion: str


def finding(rule: str, severity: str, subject: str, message: str, suggestion: str) -> Finding:
    return Finding(rule, severity, subject, message, suggestion)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"Could not read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON (line {error.lineno}).") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return value


def analyze_iam(path: Path) -> list[Finding]:
    document = load_json(path)
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise ValueError("IAM policy Statement must be an object or list of objects.")
    findings: list[Finding] = []
    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict) or str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if not isinstance(actions, list) or not isinstance(resources, list):
            continue
        action_values = [str(value) for value in actions]
        resource_values = [str(value) for value in resources]
        subject = f"Statement {index}"
        if "NotAction" in statement:
            findings.append(finding(
                "IAM005", "medium", subject, "Allow statement uses NotAction.",
                "Review the effective permission set carefully; NotAction grants everything except the listed actions.",
            ))
        if "NotResource" in statement:
            findings.append(finding(
                "IAM006", "medium", subject, "Allow statement uses NotResource.",
                "Review the effective resource scope carefully; NotResource excludes only the listed resources.",
            ))
        if "*" in action_values:
            findings.append(finding(
                "IAM001", "high", subject, "Allow statement grants every action.",
                "Replace `Action: \"*\"` with the smallest action list this workload needs.",
            ))
        elif any(value.endswith(":*") or value == "*" for value in action_values):
            findings.append(finding(
                "IAM002", "medium", subject, "Allow statement includes a wildcard action pattern.",
                "Review each wildcard action and narrow it to specific operations where possible.",
            ))
        if "*" in resource_values:
            findings.append(finding(
                "IAM003", "medium", subject, "Allow statement applies to every resource.",
                "Scope the resource to specific ARNs when the service supports resource-level permissions.",
            ))
        if any(value.lower() == "iam:passrole" or value.lower().endswith(":passrole") for value in action_values) and "*" in resource_values:
            findings.append(finding(
                "IAM004", "high", subject, "PassRole permission is not scoped to a role.",
                "Restrict PassRole to the specific role ARNs and review any iam:PassedToService condition.",
            ))
    return findings


DATE_HEADER = re.compile(r"^\d{4}-\d{2}(?:-\d{2})?$")


def _number(value: str, row_number: int) -> float:
    cleaned = value.strip().replace(",", "")
    if cleaned in {"", "-", "—"}:
        return 0.0
    try:
        return float(cleaned)
    except ValueError as error:
        raise ValueError(f"Cost value on CSV row {row_number} is not numeric.") from error


def analyze_cost(path: Path, limit: int) -> dict[str, Any]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames or []
            rows = list(reader)
    except OSError as error:
        raise ValueError(f"Could not read {path}: {error}") from error
    if not rows or len(headers) < 2:
        raise ValueError("CSV must include a header row and at least one data row.")

    lowered = {header.strip().lower(): header for header in headers}
    service_key = next((lowered[key] for key in ("service", "service name", "group") if key in lowered), None)
    period_key = lowered.get("period") or lowered.get("month") or lowered.get("date")
    cost_key = lowered.get("cost") or lowered.get("amount") or lowered.get("unblendedcost") or lowered.get("lineitem/unblendedcost")
    if service_key and period_key and cost_key:
        totals: dict[str, dict[str, float]] = {}
        for number, row in enumerate(rows, start=2):
            service = (row.get(service_key) or "").strip()
            period = (row.get(period_key) or "").strip()
            if not service or not period or service.lower() in {"total", "grand total"}:
                continue
            service_totals = totals.setdefault(service, {})
            service_totals[period] = service_totals.get(period, 0.0) + _number(row.get(cost_key, ""), number)
    else:
        # AWS Cost Explorer grouped CSVs use a row label plus one column per date.
        period_headers = [header for header in headers if DATE_HEADER.match(header.strip())]
        totals = {}
        if period_headers:
            # Grouped Cost Explorer exports can have one row per service and date columns.
            service_key = service_key or headers[0]
            periods = sorted(period_headers)
            for number, row in enumerate(rows, start=2):
                service = (row.get(service_key) or "").strip()
                if not service or service.lower() in {"total", "grand total", "forecast"}:
                    continue
                totals[service] = {period: _number(row.get(period, ""), number) for period in periods}
        else:
            # Cost Explorer can transpose chart data: one row per date, one column per service.
            first = headers[0]
            date_rows = [(number, row, (row.get(first) or "").strip()) for number, row in enumerate(rows, start=2)]
            date_rows = [(number, row, period) for number, row, period in date_rows if DATE_HEADER.match(period)]
            if not date_rows:
                raise ValueError("Unrecognized CSV. Expected service/period/cost columns or a Cost Explorer date matrix.")
            for service in headers[1:]:
                if service.strip().lower() in {"total", "grand total", "forecast"}:
                    continue
                totals[service.strip()] = {
                    period: _number(row.get(service, ""), number)
                    for number, row, period in date_rows
                }

    all_periods = sorted({period for values in totals.values() for period in values})
    if len(all_periods) < 2:
        raise ValueError("At least two cost periods are needed to compare changes.")
    previous, current = all_periods[-2:]
    changes = []
    for service, values in totals.items():
        before = values.get(previous, 0.0)
        after = values.get(current, 0.0)
        changes.append({"service": service, "previous": before, "current": after, "change": after - before})
    changes.sort(key=lambda item: item["change"], reverse=True)
    return {"previous_period": previous, "current_period": current, "changes": changes[:limit], "services_compared": len(totals)}


def analyze_kubernetes(paths: list[Path]) -> list[Finding]:
    try:
        import yaml
    except ImportError as error:
        raise ValueError("Kubernetes YAML support needs PyYAML. Install it with: python3 -m pip install -r requirements.txt") from error

    findings: list[Finding] = []
    for path in paths:
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except OSError as error:
            raise ValueError(f"Could not read {path}: {error}") from error
        except yaml.YAMLError as error:
            raise ValueError(f"Could not parse Kubernetes YAML in {path}: {error}") from error
        for document in documents:
            if not isinstance(document, dict):
                continue
            kind = str(document.get("kind", ""))
            metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
            name = str(metadata.get("name", "unnamed"))
            subject = f"{path.name}:{kind or 'Unknown'}/{name}"
            spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
            if kind == "Service" and spec.get("type") == "LoadBalancer":
                findings.append(finding("KUBE001", "medium", subject, "Service requests a load balancer.", "Confirm that public or externally routed access is intended; use an internal service where appropriate."))

            pod_spec = spec
            if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
                template = spec.get("template", {})
                pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
            elif kind == "CronJob":
                job_template = spec.get("jobTemplate", {})
                job_spec = job_template.get("spec", {}) if isinstance(job_template, dict) else {}
                template = job_spec.get("template", {}) if isinstance(job_spec, dict) else {}
                pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
            if not isinstance(pod_spec, dict):
                continue

            for volume in pod_spec.get("volumes", []) or []:
                if isinstance(volume, dict) and "hostPath" in volume:
                    findings.append(finding("KUBE002", "high", subject, "Pod mounts a hostPath volume.", "Check whether direct host filesystem access is necessary; prefer a dedicated volume or managed storage."))
                    break

            pod_security = pod_spec.get("securityContext", {})
            if isinstance(pod_security, dict) and pod_security.get("runAsNonRoot") is not True:
                findings.append(finding("KUBE003", "medium", subject, "Pod does not explicitly require a non-root user.", "Set runAsNonRoot and a compatible runAsUser where the image supports it."))

            containers = list(pod_spec.get("containers", []) or []) + list(pod_spec.get("initContainers", []) or [])
            for container in containers:
                if not isinstance(container, dict):
                    continue
                container_name = str(container.get("name", "unnamed-container"))
                container_subject = f"{subject} container {container_name}"
                security = container.get("securityContext", {})
                if isinstance(security, dict) and security.get("privileged") is True:
                    findings.append(finding("KUBE004", "high", container_subject, "Container runs in privileged mode.", "Remove privileged mode and grant only the specific capability or device the workload needs."))
                image = str(container.get("image", ""))
                image_tag = image.rsplit("/", 1)[-1].split(":")[-1] if image else ""
                if image and (":" not in image.rsplit("/", 1)[-1] or image_tag == "latest"):
                    findings.append(finding("KUBE005", "medium", container_subject, "Image is untagged or uses the mutable latest tag.", "Use a versioned tag or a verified image digest for repeatable deployments."))
                resources = container.get("resources", {})
                resources = resources if isinstance(resources, dict) else {}
                for bound in ("requests", "limits"):
                    if not isinstance(resources.get(bound), dict) or not resources[bound]:
                        findings.append(finding("KUBE006", "medium", container_subject, f"Container has no resource {bound}.", f"Set CPU and memory {bound} appropriate for the workload and validate them under load."))
    return findings


def render_findings(title: str, findings: list[Finding]) -> str:
    lines = [title]
    if not findings:
        lines.append("No findings from the current checks.")
    for item in findings:
        lines.extend([f"[{item.severity.upper()}] {item.rule} · {item.subject}: {item.message}", f"  Suggestion: {item.suggestion}"])
    lines.append("Heuristic review only. Check the full policy or manifest before deployment.")
    return "\n".join(lines)


def print_result(title: str, findings: list[Finding], as_json: bool) -> int:
    if as_json:
        print(json.dumps({"title": title, "findings": [asdict(item) for item in findings]}, indent=2))
    else:
        print(render_findings(title, findings))
    return 1 if any(item.severity == "high" for item in findings) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local, read-only checks for everyday cloud configuration files.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    iam = subparsers.add_parser("iam", help="Review an AWS IAM policy JSON document")
    iam.add_argument("file", type=Path)
    iam.add_argument("--json", action="store_true")
    cost = subparsers.add_parser("cost", help="Compare service spend from a local CSV export")
    cost.add_argument("file", type=Path)
    cost.add_argument("--limit", type=int, default=10)
    cost.add_argument("--json", action="store_true")
    kube = subparsers.add_parser("kube", help="Review Kubernetes YAML manifests")
    kube.add_argument("files", nargs="+", type=Path)
    kube.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "iam":
            findings = analyze_iam(args.file)
            return print_result("IAM Policy Quickcheck", findings, args.json)
        if args.command == "cost":
            if args.limit < 1:
                raise ValueError("--limit must be at least 1.")
            report = analyze_cost(args.file, args.limit)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(f"Cloud Cost Quickcheck — {report['previous_period']} to {report['current_period']}")
                for item in report["changes"]:
                    print(f"{item['change']:+.2f}  {item['service']} ({item['previous']:.2f} → {item['current']:.2f})")
                print("Local CSV comparison only; not a forecast or billing guarantee.")
            return 0
        findings = analyze_kubernetes(args.files)
        return print_result("Kubernetes Manifest Quickcheck", findings, args.json)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
