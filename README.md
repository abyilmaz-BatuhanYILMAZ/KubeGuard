# KubeGuard — Live Kubernetes & Offline Manifest Security Checks

**A read-only security scanner for offline Kubernetes YAML manifests and live cluster configurations.** KubeGuard applies 24 documented static checks to manifests or current Kubernetes API resource objects using an explicit kubectl context. It never changes a Kubernetes resource or executes container code.

## What it detects

- Privileged containers, privilege escalation, root user configuration and missing seccomp controls.
- Missing Linux capability restrictions and writable container root filesystems.
- Insecure `hostPath` and host namespace sharing.
- Floating image tags, missing CPU/memory limits and ServiceAccount token auto-mount.
- Overly broad Role/ClusterRole permissions and bindings to `cluster-admin`.
- Namespace manifests without a declared Pod Security Admission enforce policy.

The scanner has **24 intentionally narrow checks**. Its output is static and heuristic: a clean result is **not** a guarantee that a workload or cluster is secure. Some checks (e.g. resource limits, read-only roots, automount) are hardening recommendations, not universal Kubernetes admission requirements.

## Quick start

Requires Python 3.11+.

```bash
python -m pip install -e .
python -m kubeguard list-rules
python -m kubeguard scan examples/secure-pod.yaml
python -m kubeguard scan examples/insecure-pod.yaml
```

The insecure example is expected to return **exit status 1** at the default `--fail-on HIGH` threshold. Errors in input parsing return **exit status 2**.

```bash
kubeguard scan examples/insecure-rbac.yaml --format json --fail-on NONE
kubeguard scan examples/ --format sarif --fail-on CRITICAL > results.sarif
python -m unittest discover -s tests -v
```

## Exit status and formats

| Exit status | Meaning |
| --- | --- |
| `0` | Input parsed; no findings at/above the specified threshold |
| `1` | Findings at or above `--fail-on` (default HIGH) |
| `2` | Input or YAML parsing error; never interpreted as a clean scan |

`--format human`, `--format json`, and `--format sarif` are supported. SARIF is version 2.1.0; source positions currently point to the manifest file with a generic first-line location, while the precise Kubernetes field path appears in finding properties. Helm `{{ ... }}` templates must be rendered into valid YAML before scanning.

## Security boundaries

- KubeGuard uses a strict `SafeLoader` and rejects duplicate mapping keys.
- Files are capped at 1 MiB each. Static analysis does not interpret Helm templates or Kustomize transformations.
- In offline mode, there are no network requests or kubeconfig access. In `--cluster` mode, a locally installed `kubectl` uses the selected kubeconfig context to perform read-only Kubernetes API `get` requests. Neither mode performs vulnerability database updates or workload execution.
- The tool does not calculate actual effective RBAC privileges, account for admission-controller mutations, or verify runtime image security.
- Run it on manifests you are authorized to inspect.

## Related project

The independent **KubeSecLab** project provides step-by-step `kind` lessons with deliberately insecure and secure fixtures. Only apply the secure examples to the disposable training namespace; insecure RBAC examples are for **offline inspection only**.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Application Security Checklist](https://kubernetes.io/docs/concepts/security/application-security-checklist/)
- [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)

**License:** MIT. This project is for education and defensive configuration review, not a CIS benchmark or Kubernetes certification.

## Advanced checks

Rules `KG015–KG020` cover high-risk RBAC grants and broad NetworkPolicy peers. Scan the [advanced RBAC](examples/advanced-rbac.yaml) and [network policy](examples/insecure-network-policy.yaml) examples offline. The companion [KubeSecLab](https://github.com/abyilmaz-BatuhanYILMAZ/KubeSecLab) demonstrates live enforcement.

## Live cluster audit (read-only)

**Prerequisite:** kubectl installed and an authorized kubeconfig context with
`list` permission for all supported resources. The scanner never issues
`apply`, `patch`, `exec`, `create`, `delete`, or remote shell commands.
It reads live Kubernetes objects from the API and applies the existing 24
manifest and binding-analysis rules. No workload execution is performed by the scanner.

```bash
# Explicit context is mandatory to avoid silently auditing the wrong cluster.
kubeguard scan --cluster --context kind-kubeguard-ci --format json --fail-on NONE > audit.json

# Use a specific kubeconfig file when needed:
kubeguard scan --cluster --context my-audit-context --kubeconfig ./audit.kubeconfig --format sarif > audit.sarif
```

The live inventory covers Namespaces, Pods, major workload controllers,
Roles, RoleBindings, ClusterRoles, ClusterRoleBindings and NetworkPolicies.
Read access across all namespaces is required for namespaced resources.
The results report the Kubernetes resource name and the associated rule.
This is **static evaluation of actual API object configuration**, not packet
capture, runtime code execution, image CVE scanning or effective RBAC-graph
calculation. Cluster-scoped built-in controller roles often produce
informationally noisy hardening findings; review them before acting.

**Fail-closed behavior:** A forbidden, timed-out, oversized or invalid
response for *any* queried resource kind makes the scan incomplete and returns
exit status `2`. A partially readable cluster is **not** presented as clean.
Never provide a production admin kubeconfig to an untrusted scanner host.
Some kubeconfigs contain `exec` authentication plugins: kubectl may execute
that configured plugin when authenticating. Run this on an authorized
management workstation.

Validated against a disposable kind Kubernetes API by
[the live cluster integration workflow](.github/workflows/cluster-integration.yml).


## RBAC binding-aware analysis (v0.3)

KubeGuard now resolves **explicit** RoleBinding and ClusterRoleBinding links to
Role/ClusterRole rules and the named ServiceAccount, User or Group subject. The
additional rules are:

- KG021 HIGH: a wildcard permission actually bound to a subject.
- KG022 HIGH: a Secrets-reading permission bound to a subject.
- KG023 CRITICAL: a permission-delegation verb (bind, escalate, impersonate) bound to a subject.
- KG024 INFO: binding role reference cannot be resolved in the supplied manifest collection; do not consider its risk known.

This distinguishes an unused dangerous Role from an **assigned** dangerous
Role, including namespace-scoped RoleBindings referencing a ClusterRole.
Reports show the binding, subject, scope and source rule.

**Limits:** This is binding-resolved grant analysis, **not** the complete
effective authorization for a person. Group membership, aggregated
ClusterRoles when only partial manifests are supplied, external authorizers,
resourceNames and impersonation chains may change actual permissions.
Do not treat any clean YAML or cluster report as a penetration test.

The live-cluster GitHub Actions workflow creates a disposable ServiceAccount,
binds a broad sample Role, then asserts KG021 is reported. No cluster writes
are issued by the scanner itself.
