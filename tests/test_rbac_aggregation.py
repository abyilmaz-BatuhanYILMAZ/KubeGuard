"""Conservative, read-only aggregated ClusterRole selector tests."""
import tempfile
import unittest
from pathlib import Path

from kubeguard.scanner import scan_files


def analyze(yaml: str):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "roles.yaml"
        p.write_text(yaml, encoding="utf-8")
        return scan_files([p]).findings


BASE = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: collected}
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        security.example.net/aggregate: "true"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-grant
  labels:
    security.example.net/aggregate: "true"
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: client-role, namespace: sandbox}
roleRef: {kind: ClusterRole, name: collected, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: reader, namespace: sandbox}
"""


class AggregationTests(unittest.TestCase):
    def test_aggregation_reaches_bound_serviceaccount_with_evidence(self):
        result = analyze(BASE)
        matches = [f for f in result if f.rule_id == "KG022"]
        self.assertEqual(len(matches), 1)
        self.assertIn("ServiceAccount/sandbox/reader", matches[0].message)
        self.assertIn("origin=ClusterRole/secrets-grant", matches[0].message)
        self.assertIn("namespace=sandbox", matches[0].message)

    def test_nonmatching_label_is_not_aggregated(self):
        y = BASE.replace('security.example.net/aggregate: "true"\nrules:', 'security.example.net/aggregate: "false"\nrules:')
        result = analyze(y)
        self.assertFalse(any(f.rule_id == "KG022" for f in result))

    def test_match_expression_in_selector(self):
        y = BASE.replace(
            "    - matchLabels:\n        security.example.net/aggregate: \"true\"",
            "    - matchExpressions:\n        - key: security.example.net/aggregate\n          operator: In\n          values: [\"true\"]",
        )
        matches = [f for f in analyze(y) if f.rule_id == "KG022"]
        self.assertEqual(len(matches), 1)

    def test_aggregation_cycle_does_not_recurse_forever(self):
        cyclic = BASE.replace(
            "security.example.net/aggregate: \"true\"\nrules:",
            """security.example.net/aggregate: "true"
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        security.example.net/aggregate: "true"
rules:""",
        )
        result = analyze(cyclic)
        self.assertEqual(len([f for f in result if f.rule_id == "KG022"]), 1)

    def test_rules_already_materialized_by_controller_not_double_counted(self):
        rules = """rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
"""
        y = BASE.replace("    - matchLabels:\n        security.example.net/aggregate: \"true\"\n---",
                         "    - matchLabels:\n        security.example.net/aggregate: \"true\"\n" + rules + "---")
        result = analyze(y)
        self.assertEqual(len([f for f in result if f.rule_id == "KG022"]), 1)


if __name__ == "__main__":
    unittest.main()
