import json
import tempfile
import unittest
from pathlib import Path

from kubeguard.scanner import ManifestError, RULES, floating_image, scan_files
from kubeguard.reporting import dump

ROOT = Path(__file__).resolve().parents[1]


class ScannerTests(unittest.TestCase):
    def test_safe_pod_is_clear_of_current_rules(self):
        findings = scan_files([ROOT / "examples/secure-pod.yaml"])
        self.assertEqual(findings.documents, 1)
        self.assertEqual(findings.findings, [])

    def test_vulnerable_pod_reports_critical_and_mitigations(self):
        result = scan_files([ROOT / "examples/insecure-pod.yaml"])
        ids = {f.rule_id for f in result.findings}
        self.assertTrue({"KG001", "KG002", "KG003", "KG004", "KG005", "KG006",
                         "KG007", "KG008", "KG009", "KG010", "KG011"}.issubset(ids))
        self.assertTrue(any(f.severity == "CRITICAL" for f in result.findings))
        self.assertTrue(all(f.remediation for f in result.findings))

    def test_detects_wildcard_rbac_and_cluster_admin(self):
        result = scan_files([ROOT / "examples/insecure-rbac.yaml"])
        self.assertEqual(result.documents, 2)
        self.assertEqual({f.rule_id for f in result.findings}, {"KG012", "KG013"})

    def test_image_tag_parsing_accounts_for_registry_ports(self):
        self.assertFalse(floating_image("example.com:5000/private/app:1.2.3"))
        self.assertFalse(floating_image("example.com/private/app@sha256:123abc"))
        self.assertTrue(floating_image("example.com:5000/private/app"))
        self.assertTrue(floating_image("redis:latest"))

    def test_parser_rejects_duplicate_yaml_keys(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "duplicate.yml"
            file.write_text("apiVersion: v1\nkind: Pod\nkind: Namespace\n")
            with self.assertRaises(ManifestError):
                scan_files([file])

    def test_parser_rejects_python_object_tags(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "bad.yaml"
            file.write_text("!!python/object/apply:os.system ['echo hello']")
            with self.assertRaises(ManifestError):
                scan_files([file])

    def test_oversized_files_rejected_without_loading(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "large.yaml"
            file.write_text("x" * 1_048_577)
            with self.assertRaises(ManifestError):
                scan_files([file])

    def test_json_and_sarif_output(self):
        result = scan_files([ROOT / "examples/insecure-pod.yaml"])
        json_doc = json.loads(dump(result, "json"))
        sarif_doc = json.loads(dump(result, "sarif"))
        self.assertEqual(json_doc["schema_version"], "1.0")
        self.assertEqual(sarif_doc["version"], "2.1.0")
        self.assertEqual(len(sarif_doc["runs"][0]["results"]), len(result.findings))

    def test_all_rules_have_severity_and_remediation(self):
        self.assertGreaterEqual(len(RULES), 14)
        self.assertTrue(all(severity and title and remediation for severity, title, remediation in RULES.values()))

    def test_missing_path_is_error_not_clean_scan(self):
        with self.assertRaises(ManifestError):
            scan_files([ROOT / "examples/missing-directory"])

    def test_multi_document_namespace_and_nested_workload(self):
        manifest = """apiVersion: v1
kind: Namespace
metadata:
  name: demo
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: worker
              image: alpine:latest
"""
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "cron.yaml"
            file.write_text(manifest)
            result = scan_files([file])
            self.assertEqual(result.documents, 2)
            self.assertIn("KG014", {f.rule_id for f in result.findings})
            self.assertIn("KG007", {f.rule_id for f in result.findings})


    def test_networkpolicy_wildcards_but_not_default_deny(self):
        manifest = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-everything}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress: [{}]
  egress:
    - to: [{}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "network.yaml"
            p.write_text(manifest)
            r = scan_files([p])
            self.assertEqual({f.rule_id for f in r.findings}, {"KG017", "KG018"})
            self.assertTrue(all("deny-all" not in f.resource for f in r.findings))

    def test_internet_cidr_and_scoped_allow(self):
        manifest = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: outside}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock: {cidr: 0.0.0.0/0}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: scoped}
spec:
  podSelector: {matchLabels: {app: web}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {client: approved}}
      ports: [{protocol: TCP, port: 8080}]
"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "network.yaml"
            p.write_text(manifest)
            r = scan_files([p])
            self.assertEqual([f.rule_id for f in r.findings], ["KG019"])

    def test_rbac_risky_verbs_secrets_and_broad_subject(self):
        manifest = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: risky}
rules:
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterroles]
    verbs: [bind, escalate]
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: everyone}
subjects:
  - kind: Group
    name: system:authenticated
    apiGroup: rbac.authorization.k8s.io
roleRef: {kind: ClusterRole, name: risky, apiGroup: rbac.authorization.k8s.io}
"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rbac.yaml"
            p.write_text(manifest)
            r = scan_files([p])
            self.assertEqual({f.rule_id for f in r.findings}, {"KG015", "KG016", "KG020", "KG022", "KG023"})


if __name__ == "__main__":
    unittest.main()
