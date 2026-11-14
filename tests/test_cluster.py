"""Live cluster inventory contract tests; no real Kubernetes connection required."""
import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from kubeguard.__main__ import main
from kubeguard.cluster import RESOURCE_TYPES, scan_cluster
from kubeguard.scanner import ManifestError


def response(items, status=0):
    return subprocess.CompletedProcess(
        ["kubectl"], status, stdout=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}), stderr=""
    )


ROLE = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "Role",
    "metadata": {"name": "wild-demo", "namespace": "test"},
    "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["*"]}],
}


class ClusterContractTests(unittest.TestCase):
    @patch("kubeguard.cluster.subprocess.run")
    def test_gets_real_api_objects_for_rules(self, run):
        def fake(argv, **kwargs):
            self.assertNotIn("shell", kwargs)
            self.assertIn("--context", argv)
            self.assertIn("training-context", argv)
            self.assertIn("-o", argv)
            self.assertEqual(argv[-1], "--request-timeout=20s")
            if "roles.rbac.authorization.k8s.io" in argv:
                self.assertIn("--all-namespaces", argv)
                return response([ROLE])
            return response([])
        run.side_effect = fake
        report = scan_cluster(context="training-context")
        self.assertEqual(run.call_count, len(RESOURCE_TYPES))
        self.assertEqual(report.documents, 1)
        self.assertEqual(report.files, 0)
        self.assertEqual([f.rule_id for f in report.findings], ["KG012"])
        self.assertEqual(report.findings[0].resource, "Role/test/wild-demo")
        self.assertTrue(report.findings[0].file.startswith("cluster://training-context/"))

    @patch("kubeguard.cluster.subprocess.run")
    def test_permission_error_fails_closed(self, run):
        run.side_effect = lambda argv, **kw: (
            subprocess.CompletedProcess(argv, 1, "", "Forbidden")
            if "clusterroles.rbac.authorization.k8s.io" in argv else response([])
        )
        with self.assertRaisesRegex(ManifestError, "INCOMPLETE CLUSTER INVENTORY"):
            scan_cluster(context="test")

    @patch("kubeguard.cluster.subprocess.run")
    def test_json_parse_error_fails_closed(self, run):
        run.return_value = subprocess.CompletedProcess(["kubectl"], 0, "not JSON", "")
        with self.assertRaisesRegex(ManifestError, "malformed API JSON"):
            scan_cluster(context="test")

    @patch("kubeguard.cluster.subprocess.run")
    def test_timeout_fails_closed(self, run):
        run.side_effect = subprocess.TimeoutExpired(["kubectl"], 5)
        with self.assertRaisesRegex(ManifestError, "timed out"):
            scan_cluster(context="test")

    @patch("kubeguard.cluster.subprocess.run")
    def test_explicit_context_and_kubeconfig(self, run):
        run.return_value = response([])
        scan_cluster(context="kind-lab", kubeconfig="/tmp/lab-config", request_timeout=35)
        first = run.call_args_list[0].args[0]
        self.assertEqual(first[:5], ["kubectl", "--kubeconfig", "/tmp/lab-config", "--context", "kind-lab"])
        self.assertIn("--request-timeout=35s", first)

    @patch("kubeguard.cluster.subprocess.run")
    def test_empty_live_cluster_is_valid_when_all_reads_succeed(self, run):
        run.return_value = response([])
        result = scan_cluster(context="test")
        self.assertEqual(result.documents, 0)
        self.assertEqual(result.findings, [])

    @patch("kubeguard.cluster.subprocess.run")
    def test_cluster_cli_json_and_exit_code(self, run):
        run.side_effect = lambda args, **kwargs: response([ROLE]) if "roles.rbac.authorization.k8s.io" in args else response([])
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["scan", "--cluster", "--context", "kind-test", "--format", "json", "--fail-on", "NONE"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["findings"][0]["rule_id"], "KG012")

    def test_refuses_ambiguous_context(self):
        for name in ("", "-prod", "test name", "x" * 254):
            with self.subTest(name=name), self.assertRaises(ManifestError):
                scan_cluster(context=name)

    @patch("kubeguard.cluster.subprocess.run")
    def test_kubectl_not_found_is_error(self, run):
        run.side_effect = FileNotFoundError()
        with self.assertRaisesRegex(ManifestError, "kubectl executable"):
            scan_cluster(context="test")


if __name__ == "__main__":
    unittest.main()
