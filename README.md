# KubeGuard — Offline Kubernetes Security Checks

**A small, read-only YAML security scanner and educational reference.** KubeGuard checks Kubernetes manifests for common security weaknesses before they are deployed. It never connects to a cluster, uses kubeconfig, or executes container code.

## What it detects

- Privileged containers, privilege escalation, root user configuration and missing seccomp controls.
- Missing Linux capability restrictions and writable container root filesystems.
- Insecure `hostPath` and host namespace sharing.
- Floating image tags, missing CPU/memory limits and ServiceAccount token auto-mount.
- Overly broad Role/ClusterRole permissions and bindings to `cluster-admin`.
- Namespace manifests without a declared Pod Security Admission enforce policy.

The scanner has **14 intentionally narrow checks**. Its output is static and heuristic: a clean result is **not** a guarantee that a workload or cluster is secure. Some checks (e.g. resource limits, read-only roots, automount) are hardening recommendations, not universal Kubernetes admission requirements.

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
- No HTTP requests, kubeconfig loading, Kubernetes API access, vulnerability database updates, or workload execution.
- The tool does not calculate actual effective RBAC privileges, account for admission-controller mutations, or verify runtime image security.
- Run it on manifests you are authorized to inspect.

## Related project

The independent **KubeSecLab** project provides step-by-step `kind` lessons with deliberately insecure and secure fixtures. Only apply the secure examples to the disposable training namespace; insecure RBAC examples are for **offline inspection only**.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Application Security Checklist](https://kubernetes.io/docs/concepts/security/application-security-checklist/)
- [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)

**License:** MIT. This project is for education and defensive configuration review, not a CIS benchmark or Kubernetes certification.
