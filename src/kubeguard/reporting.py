"""Human, JSON and SARIF formatting for local manifest findings."""
from __future__ import annotations

import json
from typing import Any

from .scanner import Finding, RULES, ScanResult


def human(result: ScanResult) -> str:
    lines = [f"KubeGuard scanned {result.files} YAML file(s), {result.documents} resource document(s)."]
    for finding in result.findings:
        lines.append(f"[{finding.severity}] {finding.rule_id}: {finding.message}")
        lines.append(f"  {finding.file} (doc {finding.document}): {finding.resource} at {finding.location}")
        lines.append(f"  Fix: {finding.remediation}")
    if not result.findings:
        lines.append("No findings for the implemented checks (not a complete security assessment).")
    else:
        lines.append(f"{len(result.findings)} finding(s).")
    return "\n".join(lines)


def sarif(result: ScanResult) -> dict[str, Any]:
    rule_info = [
        {"id": rule, "shortDescription": {"text": title},
         "fullDescription": {"text": fix},
         "defaultConfiguration": {"level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}[severity]}}
        for rule, (severity, title, fix) in sorted(RULES.items())
    ]
    entries = []
    for finding in result.findings:
        entries.append({
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity in ("HIGH", "CRITICAL") else "warning",
            "message": {"text": finding.message + " — " + finding.remediation},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.file.replace('\\', '/')},
                "region": {"startLine": 1}
            }}],
            "properties": {"resource": finding.resource, "field": finding.location,
                           "document": finding.document, "severity": finding.severity},
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "KubeGuard", "informationUri": "https://kubernetes.io/docs/concepts/security/", "rules": rule_info}},
                      "results": entries}]}


def dump(result: ScanResult, style: str) -> str:
    if style == "human":
        return human(result)
    return json.dumps(result.to_dict() if style == "json" else sarif(result), indent=2, ensure_ascii=False)
