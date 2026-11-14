"""Read-only Kubernetes manifest analysis. No kubeconfig, kubectl, or cluster access."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
import yaml

MAX_BYTES = 1_048_576
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "ReplicationController"}


class ManifestError(ValueError):
    pass


class StrictSafeLoader(yaml.SafeLoader):
    """Reject silently overwritten YAML keys, including in nested mappings."""


def unique_mapping(loader: StrictSafeLoader, node: yaml.MappingNode) -> dict:
    result: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(None, None, "non-hashable YAML mapping key", key_node.start_mark) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate YAML key: {key}", key_node.start_mark)
        result[key] = loader.construct_object(value_node, deep=True)
    return result


StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    location: str
    message: str
    remediation: str
    file: str
    document: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    documents: int
    files: int

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "1.0", "files_scanned": self.files, "documents_scanned": self.documents,
                "findings": [f.as_dict() for f in self.findings],
                "counts_by_severity": {level: sum(f.severity == level for f in self.findings)
                                       for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}}


RULES: dict[str, tuple[str, str, str]] = {
    "KG001": ("CRITICAL", "Privileged container", "Remove privileged: true and grant only necessary privileges."),
    "KG002": ("HIGH", "Privilege escalation not disabled", "Set allowPrivilegeEscalation: false in the container securityContext."),
    "KG003": ("HIGH", "Non-root execution not enforced", "Set runAsNonRoot: true, and avoid runAsUser: 0."),
    "KG004": ("HIGH", "Seccomp not restricted", "Set seccompProfile.type to RuntimeDefault or a deliberate Localhost profile."),
    "KG005": ("HIGH", "Linux capabilities not minimized", "Drop ALL capabilities; add only NET_BIND_SERVICE if required."),
    "KG006": ("MEDIUM", "Writable root filesystem", "Set readOnlyRootFilesystem: true where compatible and use explicit writable volumes."),
    "KG007": ("MEDIUM", "Floating or unspecified image tag", "Use an explicit release tag or an immutable image digest."),
    "KG008": ("MEDIUM", "CPU/memory limits not defined", "Define appropriate CPU and memory resource limits for each container."),
    "KG009": ("MEDIUM", "Service account token auto-mount enabled", "Set automountServiceAccountToken: false unless the workload requires Kubernetes API access."),
    "KG010": ("HIGH", "hostPath volume", "Avoid hostPath volumes; prefer an explicit PVC or supported ephemeral volume."),
    "KG011": ("HIGH", "Host namespace sharing", "Disable hostNetwork, hostPID and hostIPC unless justified by a reviewed infrastructure workload."),
    "KG012": ("HIGH", "Wildcard RBAC permission", "Specify only the apiGroups, resources and verbs the role actually needs."),
    "KG013": ("CRITICAL", "cluster-admin role binding", "Avoid binding cluster-admin; grant a limited, scoped Role wherever possible."),
    "KG014": ("MEDIUM", "Namespace not enforcing Pod Security", "Label the namespace pod-security.kubernetes.io/enforce with a suitable policy such as restricted."),
    "KG015": ("HIGH", "Risky RBAC privilege verb", "Review and minimize escalate, bind, impersonate grants."),
    "KG016": ("MEDIUM", "Permission to read Kubernetes Secrets", "Review get/list/watch access to Secrets; scope when possible."),
    "KG017": ("HIGH", "Open NetworkPolicy ingress", "Restrict ingress sources with pod/namespace selectors."),
    "KG018": ("HIGH", "Open NetworkPolicy egress", "Restrict egress destinations and ports."),
    "KG019": ("MEDIUM", "Wide Internet CIDR", "Review 0.0.0.0/0 or ::/0 destination and any NAT effects."),
    "KG020": ("HIGH", "Broad RBAC binding subject", "Avoid broad system groups or anonymous users as RBAC subjects."),
}


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def sequence(value: object) -> list:
    return value if isinstance(value, list) else []


def resource_id(obj: dict) -> str:
    metadata = mapping(obj.get("metadata"))
    return f"{obj.get('kind', '?')}/{metadata.get('namespace', 'default')}/{metadata.get('name', '?')}"


def get_pod_spec(obj: dict) -> dict:
    kind = obj.get("kind")
    if kind == "Pod":
        return mapping(obj.get("spec"))
    if kind == "CronJob":
        job = mapping(mapping(obj.get("spec")).get("jobTemplate"))
        template = mapping(mapping(job.get("spec")).get("template"))
        return mapping(template.get("spec"))
    if kind in WORKLOADS:
        template = mapping(mapping(obj.get("spec")).get("template"))
        return mapping(template.get("spec"))
    return {}


def floating_image(image: object) -> bool:
    if not isinstance(image, str) or not image.strip():
        return True
    if "@sha256:" in image.lower():
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest") or last.endswith(":")


def scan_resource(obj: dict, file_name: str, doc_num: int) -> list[Finding]:
    findings: list[Finding] = []
    identity = resource_id(obj)
    kind = obj.get("kind")

    def add(rule: str, location: str, info: str = "") -> None:
        severity, message, fix = RULES[rule]
        findings.append(Finding(rule, severity, identity, location, message + (f": {info}" if info else ""), fix, file_name, doc_num))

    if kind in WORKLOADS:
        pod = get_pod_spec(obj)
        pod_sc = mapping(pod.get("securityContext"))
        if pod.get("automountServiceAccountToken") is not False:
            add("KG009", "spec.automountServiceAccountToken")
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if pod.get(field) is True:
                add("KG011", f"spec.{field}", field)
        for idx, volume in enumerate(sequence(pod.get("volumes"))):
            if "hostPath" in mapping(volume):
                add("KG010", f"spec.volumes[{idx}].hostPath")
        for container_type in ("containers", "initContainers", "ephemeralContainers"):
            for idx, c in enumerate(sequence(pod.get(container_type))):
                c = mapping(c)
                c_sc = mapping(c.get("securityContext"))
                prefix = f"spec.{container_type}[{idx}]({c.get('name', '?')})"
                if c_sc.get("privileged") is True:
                    add("KG001", prefix + ".securityContext.privileged")
                if c_sc.get("allowPrivilegeEscalation") is not False:
                    add("KG002", prefix + ".securityContext.allowPrivilegeEscalation")
                nonroot = c_sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
                user = c_sc.get("runAsUser", pod_sc.get("runAsUser"))
                if nonroot is not True or user == 0:
                    add("KG003", prefix + ".securityContext.runAsNonRoot")
                seccomp = c_sc.get("seccompProfile", pod_sc.get("seccompProfile"))
                if mapping(seccomp).get("type") not in ("RuntimeDefault", "Localhost"):
                    add("KG004", prefix + ".securityContext.seccompProfile")
                caps = mapping(c_sc.get("capabilities"))
                dropped = sequence(caps.get("drop"))
                added = sequence(caps.get("add"))
                if "ALL" not in dropped or any(x != "NET_BIND_SERVICE" for x in added):
                    add("KG005", prefix + ".securityContext.capabilities")
                if c_sc.get("readOnlyRootFilesystem") is not True:
                    add("KG006", prefix + ".securityContext.readOnlyRootFilesystem")
                if floating_image(c.get("image")):
                    add("KG007", prefix + ".image", str(c.get("image", "unspecified")))
                limits = mapping(mapping(c.get("resources")).get("limits"))
                if not all(limits.get(key) for key in ("cpu", "memory")):
                    add("KG008", prefix + ".resources.limits")
    if kind in ("Role", "ClusterRole"):
        for idx, rule in enumerate(sequence(obj.get("rules"))):
            rule = mapping(rule)
            verbs = set(str(v) for v in sequence(rule.get("verbs")))
            resources = set(str(v) for v in sequence(rule.get("resources")))
            if any("*" in sequence(rule.get(f)) for f in ("verbs", "resources", "apiGroups", "nonResourceURLs")):
                add("KG012", f"rules[{idx}]")
            if verbs & {"escalate", "bind", "impersonate"}:
                add("KG015", f"rules[{idx}].verbs")
            if "secrets" in resources and verbs & {"get", "list", "watch"}:
                add("KG016", f"rules[{idx}].resources")
    if kind in ("ClusterRoleBinding", "RoleBinding"):
        ref = mapping(obj.get("roleRef"))
        if ref.get("kind") == "ClusterRole" and ref.get("name") == "cluster-admin":
            add("KG013", "roleRef")
        broad = {"system:authenticated", "system:unauthenticated", "system:serviceaccounts"}
        for idx, subject in enumerate(sequence(obj.get("subjects"))):
            subject = mapping(subject)
            if ((subject.get("kind") == "Group" and subject.get("name") in broad) or
                (subject.get("kind") == "User" and subject.get("name") == "system:anonymous")):
                add("KG020", f"subjects[{idx}]")
    if kind == "NetworkPolicy":
        spec = mapping(obj.get("spec"))
        types = set(str(v) for v in sequence(spec.get("policyTypes")))
        if not types:
            types = {"Ingress"}
            if "egress" in spec:
                types.add("Egress")
        for direction, rule_id, field in (("Ingress", "KG017", "from"), ("Egress", "KG018", "to")):
            if direction not in types:
                continue
            for idx, item in enumerate(sequence(spec.get(direction.lower()))):
                rule = mapping(item)
                peers = sequence(rule.get(field))
                # Omitted peer key or an empty peer object means unrestricted.
                # An empty peer ARRAY does not, and is not flagged here.
                if field not in rule or any(isinstance(peer, dict) and not peer for peer in peers):
                    add(rule_id, f"spec.{direction.lower()}[{idx}].{field}")
                if direction == "Egress":
                    for pidx, peer in enumerate(peers):
                        cidr = mapping(mapping(peer).get("ipBlock")).get("cidr")
                        if cidr in ("0.0.0.0/0", "::/0"):
                            add("KG019", f"spec.egress[{idx}].to[{pidx}].ipBlock.cidr")
    if kind == "Namespace":
        labels = mapping(mapping(obj.get("metadata")).get("labels"))
        if labels.get("pod-security.kubernetes.io/enforce") not in ("restricted", "baseline"):
            add("KG014", "metadata.labels.pod-security.kubernetes.io/enforce")
    return findings


def discover(paths: Iterable[str | Path]) -> list[Path]:
    files = set()
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.update(f for f in path.rglob("*") if f.is_file() and f.suffix.lower() in (".yaml", ".yml"))
        elif path.is_file() and path.suffix.lower() in (".yaml", ".yml"):
            files.add(path)
        else:
            raise ManifestError(f"No YAML file or directory found: {path}")
    if not files:
        raise ManifestError("No .yaml/.yml manifests found")
    return sorted(files)


def scan_files(paths: Iterable[str | Path]) -> ScanResult:
    files = discover(paths)
    findings: list[Finding] = []
    documents = 0
    for file in files:
        if file.stat().st_size > MAX_BYTES:
            raise ManifestError(f"YAML exceeds {MAX_BYTES} bytes: {file}")
        try:
            text = file.read_text(encoding="utf-8")
            objs = list(yaml.load_all(text, Loader=StrictSafeLoader))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ManifestError(f"Cannot safely parse {file}: {exc}") from exc
        if not objs or all(o is None for o in objs):
            raise ManifestError(f"Empty manifest: {file}")
        for number, obj in enumerate(objs, 1):
            if obj is None:
                continue
            if not isinstance(obj, dict) or not isinstance(obj.get("kind"), str) or not isinstance(obj.get("apiVersion"), str):
                raise ManifestError(f"Expected Kubernetes resource with apiVersion and kind in {file}, document {number}")
            documents += 1
            if obj["kind"] == "List":
                items = obj.get("items")
                if not isinstance(items, list):
                    raise ManifestError(f"Invalid Kubernetes List in {file}, document {number}")
                for child in items:
                    if not isinstance(child, dict) or not isinstance(child.get("kind"), str):
                        raise ManifestError(f"Invalid List child in {file}, document {number}")
                    findings.extend(scan_resource(child, str(file), number))
            else:
                findings.extend(scan_resource(obj, str(file), number))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.document, f.resource, f.rule_id, f.location))
    return ScanResult(findings, documents, len(files))
