"""Smoke tests for K8SAUDIT. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from k8saudit import TOOL_NAME, TOOL_VERSION, audit_text, load_documents  # noqa: E402
from k8saudit.cli import main, _render_html, build_parser  # noqa: E402


INSECURE = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: prod
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
          env:
            - name: DB_PASSWORD
              value: plaintext123
"""

SECURE = """
apiVersion: v1
kind: Pod
metadata:
  name: good
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: registry.example.com/app@sha256:abc
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 1000
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: "500m"
          memory: 256Mi
"""


class TestLoader(unittest.TestCase):
    def test_yaml_multidoc(self):
        docs = load_documents(INSECURE + "\n---\n" + SECURE)
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0]["kind"], "Deployment")
        self.assertEqual(docs[1]["kind"], "Pod")

    def test_json_input(self):
        obj = {"kind": "Pod", "metadata": {"name": "j"},
               "spec": {"containers": [{"name": "c", "image": "x:1",
                        "securityContext": {"privileged": True}}]}}
        docs = load_documents(json.dumps(obj))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["kind"], "Pod")

    def test_nested_parse(self):
        docs = load_documents(INSECURE)
        spec = docs[0]["spec"]["template"]["spec"]
        self.assertTrue(spec["hostNetwork"])
        self.assertEqual(spec["containers"][0]["name"], "api")


class TestEngine(unittest.TestCase):
    def test_insecure_flags_many(self):
        report = audit_text(INSECURE)
        self.assertEqual(report.workloads_scanned, 1)
        ids = {f.rule_id for f in report.findings}
        for expected in ("K8S-001", "K8S-002", "K8S-007", "K8S-009", "K8S-012"):
            self.assertIn(expected, ids)
        self.assertTrue(report.failed)

    def test_secure_is_clean(self):
        report = audit_text(SECURE)
        self.assertEqual(report.workloads_scanned, 1)
        self.assertEqual(report.findings, [])
        self.assertFalse(report.failed)

    def test_counts_consistent(self):
        report = audit_text(INSECURE)
        self.assertEqual(sum(report.counts.values()), len(report.findings))


class TestCli(unittest.TestCase):
    def test_version_and_constants(self):
        self.assertEqual(TOOL_NAME, "k8saudit")
        self.assertTrue(TOOL_VERSION)

    def test_exit_code_findings(self):
        import io
        from contextlib import redirect_stdout
        path = os.path.join(os.path.dirname(__file__), "_tmp_insecure.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(INSECURE)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path, "--format", "json"])
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            self.assertGreater(len(data["findings"]), 0)
        finally:
            os.remove(path)

    def test_exit_code_clean(self):
        import io
        from contextlib import redirect_stdout
        path = os.path.join(os.path.dirname(__file__), "_tmp_secure.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(SECURE)
        try:
            with redirect_stdout(io.StringIO()):
                rc = main(["scan", path])
            self.assertEqual(rc, 0)
        finally:
            os.remove(path)

    def test_html_render(self):
        report = audit_text(INSECURE)
        out = _render_html(report)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("K8SAUDIT".lower(), out.lower())
        self.assertIn("K8S-001", out)

    def test_min_severity_filter(self):
        import io
        from contextlib import redirect_stdout
        path = os.path.join(os.path.dirname(__file__), "_tmp_min.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(INSECURE)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["scan", path, "--format", "json", "--min-severity", "CRITICAL"])
            data = json.loads(buf.getvalue())
            for f in data["findings"]:
                self.assertEqual(f["severity"], "CRITICAL")
        finally:
            os.remove(path)

    def test_parser_builds(self):
        self.assertIsNotNone(build_parser())


if __name__ == "__main__":
    unittest.main()
