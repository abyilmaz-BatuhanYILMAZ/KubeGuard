import contextlib
import io
import json
import unittest
from pathlib import Path

from kubeguard.__main__ import main

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_safe_is_zero(self):
        code, output, error = self.invoke("scan", str(ROOT / "examples/secure-pod.yaml"))
        self.assertEqual(code, 0)
        self.assertIn("No findings", output)
        self.assertEqual(error, "")

    def test_insecure_is_nonzero(self):
        code, output, error = self.invoke("scan", str(ROOT / "examples/insecure-pod.yaml"))
        self.assertEqual(code, 1)
        self.assertIn("[CRITICAL] KG001", output)
        self.assertEqual(error, "")

    def test_json_results_and_threshold(self):
        code, output, _ = self.invoke("scan", str(ROOT / "examples/insecure-pod.yaml"), "--format", "json", "--fail-on", "NONE")
        self.assertEqual(code, 0)
        self.assertGreater(json.loads(output)["counts_by_severity"]["HIGH"], 0)

    def test_missing_source_is_error(self):
        code, _, error = self.invoke("scan", "not-found.yml")
        self.assertEqual(code, 2)
        self.assertIn("input error", error)

    def test_list_rules(self):
        code, output, error = self.invoke("list-rules")
        self.assertEqual(code, 0)
        self.assertIn("KG013", output)
        self.assertEqual(error, "")


if __name__ == "__main__":
    unittest.main()
