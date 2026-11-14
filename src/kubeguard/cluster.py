"""Read-only inventory of Kubernetes API resources using an explicit kubectl context.

No shell execution and no Kubernetes writes. An incomplete inventory raises an
error instead of silently presenting a clean security report.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from .scanner import Finding, ManifestError, ScanResult, SEVERITY_ORDER, scan_resource

# Fully-qualified resources prevent ambiguity with CRDs and API aliases.
# Namespace resources are cluster-scoped; all others use --all-namespaces.
RESOURCE_TYPES: tuple[tuple[str, bool], ...] = (
    ("namespaces", False),
    ("pods", True),
    ("deployments.apps", True),
    ("statefulsets.apps", True),
    ("daemonsets.apps", True),
    ("jobs.batch", True),
    ("cronjobs.batch", True),
    ("replicasets.apps", True),
    ("replicationcontrollers", True),
    ("roles.rbac.authorization.k8s.io", True),
    ("rolebindings.rbac.authorization.k8s.io", True),
    ("clusterroles.rbac.authorization.k8s.io", False),
    ("clusterrolebindings.rbac.authorization.k8s.io", False),
    ("networkpolicies.networking.k8s.io", True),
)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def _validate_context(context: str) -> None:
    if not isinstance(context, str) or not re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,253}", context):
        raise ManifestError("A literal, explicit --context name is required for cluster scans")
    if context.startswith("-"):
        raise ManifestError("--context must not begin with '-' ")


def scan_cluster(*, context: str, kubeconfig: str | None = None,
                 request_timeout: int = 20) -> ScanResult:
    """Inventory supported API kinds. Requires list access for every kind.

    Raises ManifestError if any read fails; a partial scan must not look clean.
    The API sends objects in JSON; only derived static findings are persisted.
    """
    _validate_context(context)
    if not isinstance(request_timeout, int) or not 5 <= request_timeout <= 120:
        raise ManifestError("request timeout must be between 5 and 120 seconds")
    if kubeconfig is not None and (not kubeconfig or "\x00" in kubeconfig):
        raise ManifestError("Invalid kubeconfig path")
    command = ["kubectl"]
    if kubeconfig:
        command += ["--kubeconfig", kubeconfig]
    command += ["--context", context]

    findings: list[Finding] = []
    scanned = 0
    errors: list[str] = []
    for resource_type, namespaced in RESOURCE_TYPES:
        args = [*command, "get", resource_type]
        if namespaced:
            args.append("--all-namespaces")
        args += ["-o", "json", f"--request-timeout={request_timeout}s"]
        try:
            completed = subprocess.run(
                args, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=request_timeout + 15, check=False,
            )
        except FileNotFoundError:
            raise ManifestError("kubectl executable not found; install kubectl first") from None
        except subprocess.TimeoutExpired:
            errors.append(f"{resource_type}: API request timed out")
            continue
        except OSError:
            errors.append(f"{resource_type}: kubectl could not be executed")
            continue
        if completed.returncode:
            # Never echo raw stderr: credentials, server addresses or provider
            # diagnostics may appear there.
            errors.append(f"{resource_type}: Kubernetes API read failed (kubectl exit {completed.returncode})")
            continue
        if len(completed.stdout.encode("utf-8")) > MAX_RESPONSE_BYTES:
            errors.append(f"{resource_type}: response exceeded safety size limit")
            continue
        try:
            obj: Any = json.loads(completed.stdout)
            if not isinstance(obj, dict) or not isinstance(obj.get("items"), list):
                raise ValueError("expected Kubernetes List with items")
            items = obj["items"]
            if any(not isinstance(item, dict) or not isinstance(item.get("kind"), str)
                   or not isinstance(item.get("apiVersion"), str) for item in items):
                raise ValueError("Kubernetes List contains invalid resource objects")
        except (ValueError, TypeError):
            errors.append(f"{resource_type}: malformed API JSON response")
            continue
        for item in items:
            scanned += 1
            findings.extend(scan_resource(item, f"cluster://{context}/{resource_type}", scanned))

    if errors:
        # A principal restricted to part of the cluster cannot assert there
        # are zero findings. Explain which read operations were incomplete.
        raise ManifestError("INCOMPLETE CLUSTER INVENTORY — " + "; ".join(errors)
                            + ". Request read-only list permissions or use offline YAML scanning.")
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.resource, f.rule_id, f.location))
    return ScanResult(findings=findings, documents=scanned, files=0)
