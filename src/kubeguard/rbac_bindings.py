"""Resolve explicit Kubernetes RBAC RoleBinding/ClusterRoleBinding grants.

This is binding-aware static analysis, not complete effective-user authorization.
Group membership, admission, impersonation, aggregation changes and external
authorizers require additional verification.
"""
from __future__ import annotations

from typing import Any

from .scanner import Finding, RULES, mapping, sequence, resource_id


def binding_findings(records: list[tuple[dict[str, Any], str, int]]) -> list[Finding]:
    roles: dict[tuple[str, str, str], dict[str, Any]] = {}
    for obj, _, _ in records:
        kind = obj.get("kind")
        if kind not in ("Role", "ClusterRole"):
            continue
        meta = mapping(obj.get("metadata"))
        namespace = str(meta.get("namespace") or "default") if kind == "Role" else ""
        name = str(meta.get("name") or "")
        if name:
            roles[(kind, namespace, name)] = obj

    findings: list[Finding] = []
    for obj, file_name, doc_num in records:
        kind = obj.get("kind")
        if kind not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        meta = mapping(obj.get("metadata"))
        ns = str(meta.get("namespace") or "default") if kind == "RoleBinding" else ""
        role_ref = mapping(obj.get("roleRef"))
        target_kind = role_ref.get("kind")
        target_name = str(role_ref.get("name") or "")
        if target_kind not in ("Role", "ClusterRole"):
            continue
        if kind == "ClusterRoleBinding" and target_kind != "ClusterRole":
            continue
        role_key = (target_kind, ns if target_kind == "Role" else "", target_name)
        role = roles.get(role_key)
        if role is None:
            # Do not claim the binding is harmless if the role is unavailable.
            _append(findings, "KG024", obj, file_name, doc_num, "roleRef",
                    f"Could not resolve {target_kind}/{target_name}; effective grants unknown")
            continue

        for subindex, subject in enumerate(sequence(obj.get("subjects"))):
            subject = mapping(subject)
            subject_kind = str(subject.get("kind") or "?")
            subject_name = str(subject.get("name") or "?")
            if subject_kind not in ("User", "Group", "ServiceAccount"):
                continue
            sub_ns = str(subject.get("namespace") or ns) if subject_kind == "ServiceAccount" else ""
            identity = f"{subject_kind}/{sub_ns + '/' if sub_ns else ''}{subject_name}"
            for rule_index, rule in enumerate(sequence(role.get("rules"))):
                rule = mapping(rule)
                verbs = set(str(x) for x in sequence(rule.get("verbs")))
                resources = set(str(x) for x in sequence(rule.get("resources")))
                apigroups = set(str(x) for x in sequence(rule.get("apiGroups")))
                nonresource = set(str(x) for x in sequence(rule.get("nonResourceURLs")))
                path = f"subjects[{subindex}] -> {target_kind}/{target_name}.rules[{rule_index}]"
                scope = "cluster-wide" if kind == "ClusterRoleBinding" else f"namespace={ns}"
                details = f"{identity}, {scope}; {path}"
                if "*" in verbs or "*" in resources or "*" in apigroups or "*" in nonresource:
                    _append(findings, "KG021", obj, file_name, doc_num, path, details)
                if ("secrets" in resources or "*" in resources) and verbs.intersection(
                    {"get", "list", "watch", "*"}
                ):
                    _append(findings, "KG022", obj, file_name, doc_num, path, details)
                if verbs.intersection({"escalate", "bind", "impersonate"}):
                    _append(findings, "KG023", obj, file_name, doc_num, path, details)
    return findings


def _append(findings: list[Finding], rule: str, obj: dict,
            source: str, doc_num: int, path: str, explanation: str) -> None:
    severity, message, fix = RULES[rule]
    findings.append(Finding(
        rule_id=rule,
        severity=severity,
        resource=resource_id(obj),
        location=path,
        message=f"{message}: {explanation}",
        remediation=fix,
        file=source,
        document=doc_num,
    ))
