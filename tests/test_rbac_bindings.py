"""Tests for direct RBAC binding resolution (not the full group membership graph)."""
import tempfile
import unittest
from pathlib import Path

from kubeguard.scanner import scan_files


def findings(yaml_text: str):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "rbac.yaml"
        path.write_text(yaml_text, encoding="utf-8")
        return scan_files([path]).findings


ROLE = """apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: secret-reader, namespace: audit}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
  - apiGroups: [""]
    resources: [configmaps]
    verbs: ["*"]
"""
BINDING = """apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: sa-grant, namespace: audit}
roleRef: {kind: Role, name: secret-reader, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: reader, namespace: audit}
"""


class BindingTests(unittest.TestCase):
    def test_unbound_role_is_not_a_bound_permission(self):
        ids = {f.rule_id for f in findings(ROLE)}
        self.assertIn("KG012", ids)
        self.assertIn("KG016", ids)
        self.assertNotIn("KG021", ids)
        self.assertNotIn("KG022", ids)

    def test_rolebinding_connects_grant_and_specific_identity(self):
        rows = findings(ROLE + "---\n" + BINDING)
        ids = {f.rule_id for f in rows}
        self.assertTrue({"KG021", "KG022"}.issubset(ids))
        bound = [f for f in rows if f.rule_id in ("KG021", "KG022")]
        self.assertTrue(all("ServiceAccount/audit/reader" in f.message for f in bound))
        self.assertTrue(all(f.resource == "RoleBinding/audit/sa-grant" for f in bound))
        self.assertTrue(all("namespace=audit" in f.message for f in bound))

    def test_clusterrolebinding_escalation_grant(self):
        manifest = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: delegator}
rules:
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterroles]
    verbs: [bind, escalate]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: delegation}
roleRef: {kind: ClusterRole, name: delegator, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: Group, name: operators}
"""
        rows = findings(manifest)
        bound = [f for f in rows if f.rule_id == "KG023"]
        self.assertEqual(len(bound), 1)
        self.assertIn("Group/operators", bound[0].message)
        self.assertIn("cluster-wide", bound[0].message)

    def test_rolebinding_to_clusterrole_uses_binding_namespace(self):
        manifest = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: templated-secrets}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: scoped, namespace: sandbox}
roleRef: {kind: ClusterRole, name: templated-secrets, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: svc}
"""
        rows = findings(manifest)
        secret = [f for f in rows if f.rule_id == "KG022"]
        self.assertEqual(len(secret), 1)
        self.assertIn("namespace=sandbox", secret[0].message)
        self.assertIn("ServiceAccount/sandbox/svc", secret[0].message)

    def test_unknown_role_ref_fails_to_silent_clean_scan(self):
        manifest = """apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: dangling, namespace: sandbox}
roleRef: {kind: Role, name: missing, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: User, name: bob}
"""
        rows = findings(manifest)
        self.assertEqual([f.rule_id for f in rows], ["KG024"])

    def test_name_collisions_do_not_link_wrong_namespaces(self):
        wrong_namespace = ROLE.replace("namespace: audit", "namespace: other")
        rows = findings(wrong_namespace + "---\n" + BINDING)
        self.assertIn("KG024", {f.rule_id for f in rows})
        self.assertNotIn("KG022", {f.rule_id for f in rows})


if __name__ == "__main__":
    unittest.main()
