"""Resolve explicit Kubernetes RBAC RoleBinding/ClusterRoleBinding grants.

This is binding-aware static analysis, not complete effective-user authorization.
Group membership, admission, impersonation, aggregation changes and external
authorizers require additional verification.
"""
from __future__ import annotations

from typing import Any

from .scanner import Finding, RULES, mapping, sequence, resource_id


def _matches_selector(selector: dict, labels: dict) -> bool:
    """Evaluate Kubernetes matchLabels and matchExpressions selectors."""
    for key, value in mapping(selector.get("matchLabels")).items():
        if labels.get(key) != value:
            return False
    for expression in sequence(selector.get("matchExpressions")):
        expression = mapping(expression)
        key = expression.get("key")
        operator = expression.get("operator")
        if not isinstance(key, str) or not key:
            return False
        values = set(str(v) for v in sequence(expression.get("values")))
        present = key in labels
        if operator == "In":
            if not present or str(labels[key]) not in values:
                return False
        elif operator == "NotIn":
            if present and str(labels[key]) in values:
                return False
        elif operator == "Exists":
            if not present:
                return False
        elif operator == "DoesNotExist":
            if present:
                return False
        else:
            return False
    return True


def _role_rules(
    role: dict[str, Any],
    cluster_roles: dict[str, dict[str, Any]],
    visited: set[str],
) -> list[tuple[dict, str]]:
    """Expand aggregated ClusterRoles for an offline snapshot.

    The API generally already contains controller-generated rules. Include
    explicit rules and selector matches, deduplicating equivalent grants.
    """
    from json import dumps
    result: list[tuple[dict, str]] = []
    seen: set[str] = set()

    def add(rule: dict, source: str) -> None:
        key = dumps(rule, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            result.append((rule, source))

    name = str(mapping(role.get("metadata")).get("name") or "?")
    for rule in sequence(role.get("rules")):
        add(mapping(rule), name)
    selectors = sequence(mapping(role.get("aggregationRule")).get("clusterRoleSelectors"))
    if not selectors:
        return result
    for other_name, other in cluster_roles.items():
        if other_name == name or other_name in visited:
            continue
        labels = mapping(mapping(other.get("metadata")).get("labels"))
        if any(_matches_selector(mapping(selector), labels) for selector in selectors):
            for rule, origin in _role_rules(other, cluster_roles, visited | {name, other_name}):
                add(rule, origin)
    return result


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

    cluster_roles = {key[2]: role for key, role in roles.items() if key[0] == "ClusterRole"}
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
        if role is None and target_kind == "ClusterRole" and target_name == "cluster-admin":
            # Kubernetes built-in cluster-admin role exists on normal clusters;
            # the direct binding check KG013 already covers this case.
            continue
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
            resolved = (_role_rules(role, cluster_roles, {target_name})
                        if target_kind == "ClusterRole"
                        else [(mapping(rule), target_name) for rule in sequence(role.get("rules"))])
            for rule_index, (rule, origin) in enumerate(resolved):
                rule = mapping(rule)
                verbs = set(str(x) for x in sequence(rule.get("verbs")))
                resources = set(str(x) for x in sequence(rule.get("resources")))
                apigroups = set(str(x) for x in sequence(rule.get("apiGroups")))
                nonresource = set(str(x) for x in sequence(rule.get("nonResourceURLs")))
                path = f"subjects[{subindex}] -> {target_kind}/{target_name}.rules[{rule_index}]"
                scope = "cluster-wide" if kind == "ClusterRoleBinding" else f"namespace={ns}"
                details = (f"{identity}, {scope}; {path}; origin=ClusterRole/{origin}"
                           if target_kind == "ClusterRole" else f"{identity}, {scope}; {path}")
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
