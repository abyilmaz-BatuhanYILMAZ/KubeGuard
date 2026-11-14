# KubeGuard static rule catalog

These checks are an **educational subset** of Kubernetes Pod Security Standards and hardening guidance. The severity levels reflect the static tool's conservative triage choices; they are not CVSS scores, and only some map to restricted Pod Security Admission.

| ID | Severity | Detection | Suggested correction |
| --- | --- | --- | --- |
| KG001 | CRITICAL | Container `privileged: true` | Remove privileged mode |
| KG002 | HIGH | Missing `allowPrivilegeEscalation: false` | Disable escalation |
| KG003 | HIGH | Missing `runAsNonRoot: true` or UID 0 | Enforce non-root |
| KG004 | HIGH | Missing RuntimeDefault/Localhost seccomp profile | Set seccomp |
| KG005 | HIGH | Missing drop ALL, or excessive added capabilities | Restrict capabilities |
| KG006 | MEDIUM | Missing readOnlyRootFilesystem | Prefer immutable root filesystem |
| KG007 | MEDIUM | Image uses `latest` or no explicit tag | Pin a tag or digest |
| KG008 | MEDIUM | Missing CPU/memory limit | Define limits |
| KG009 | MEDIUM | Default automount of ServiceAccount token | Disable unless needed |
| KG010 | HIGH | `hostPath` volume | Remove access to node filesystem |
| KG011 | HIGH | `hostPID`, `hostIPC`, `hostNetwork` true | Disable host namespace sharing |
| KG012 | HIGH | RBAC wildcard | Scope resource and verb grants |
| KG013 | CRITICAL | Binding to cluster-admin | Replace with least-privilege Role |
| KG014 | MEDIUM | Namespace missing restricted/baseline enforcement | Add appropriate Pod Security label |

## Implementation limitations

- Linux-oriented restricted checks may be inappropriate for Windows Pod security contexts; there is no Windows-aware exemption in this initial release.
- The tool checks supported direct workload templates, not computed Helm/Kustomize output or live admission results.
- Pod inheritance of `runAsNonRoot` and `seccompProfile` is implemented; it does not resolve arbitrary policy or admission mutation.
- No cross-resource policy exists: e.g. the absence of NetworkPolicy cannot be inferred from a single Pod YAML, and RBAC binding evaluation is not a complete graph analysis.
- A manifest may pass these checks while still being vulnerable. Pair with admission enforcement, image analysis, runtime monitoring and authorization review.

Authoritative sources: [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/), [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Advanced RBAC and NetworkPolicy checks

| Rule | Severity | Checks |
| --- | --- | --- |
| KG015 | HIGH | `escalate`, `bind` and `impersonate` RBAC verbs |
| KG016 | MEDIUM | `get/list/watch` permissions on Secrets |
| KG017 | HIGH | NetworkPolicy ingress rule open to all sources |
| KG018 | HIGH | NetworkPolicy egress rule open to all destinations |
| KG019 | MEDIUM | Wide Internet ipBlock `0.0.0.0/0` / `::/0` |
| KG020 | HIGH | Broad built-in RBAC groups or anonymous user subject |

These are **static heuristics**. They do not resolve live cluster authorization, role aggregation, CNI enforcement, or the absence of policies in a namespace. `from: []` / `to: []` are not treated as unrestricted peers.

## Live cluster scope

With `kubeguard scan --cluster --context NAME`, KubeGuard retrieves Kubernetes
API resource objects using **kubectl get** and applies the same `KG001–KG020`
rules as it does to YAML. It queries supported namespaced workload resources,
Namespaced RBAC, Cluster RBAC, Namespace objects and NetworkPolicy objects.

- Access: Kubernetes API read-only `list` on all supported resource kinds,
  plus network/authentication to that cluster.
- No write, mutation, external command execution beyond local `kubectl`, or
  container execution.
- All supported API kind queries must succeed: incomplete inventory exits 2.
- Cluster-scoped RBAC objects may reflect normal control-plane permissions
  which require human triage.
- Static results cannot prove NetworkPolicy enforcement or derive the entire
  effective authorization graph.


## Binding-aware rules (v0.4)

| ID | Severity | Scope |
| --- | --- | --- |
| KG021 | HIGH | RBAC wildcard attached through an explicit RoleBinding or ClusterRoleBinding |
| KG022 | HIGH | Explicitly bound permission to read/list/watch Secrets |
| KG023 | CRITICAL | Explicitly bound bind/escalate/impersonate permission |
| KG024 | INFO | Referenced Role/ClusterRole not supplied; do not infer the binding is safe |

The binding engine links a RoleBinding to a same-namespace Role or to a
ClusterRole, and links a ClusterRoleBinding to a ClusterRole. It records
ServiceAccount/namespace and User/Group identities as found in the
binding. It expands label-selected aggregated ClusterRole rules from the collected objects; it does not expand external user-to-group membership or produce a complete effective-permissions graph.

Cluster-admin bindings already have the direct KG013 rule. Offline YAML
with an absent built-in cluster-admin definition is not treated as an
unknown role, because Kubernetes supplies that built-in role.

Kubernetes aggregation rules are reconciled by the control plane. KubeGuard's
`aggregationRule.clusterRoleSelectors` matching is an **observed-snapshot
approximation** with explicit Role/ClusterRoleBindings; it does not prove
what the Kubernetes authorization API currently permits for any external user.
