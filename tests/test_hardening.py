"""Hardening tests: edge cases, bad input, error paths. Standard library only."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from k8saudit import audit_text, load_documents  # noqa: E402
from k8saudit.cli import main  # noqa: E402


class TestEdgeCasesCore(unittest.TestCase):
    """Edge cases in the core engine."""

    def test_empty_string_returns_empty_report(self):
        """Empty input should produce zero documents, zero findings, no errors."""
        report = audit_text("")
        self.assertEqual(report.documents_scanned, 0)
        self.assertEqual(report.workloads_scanned, 0)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.errors, [])

    def test_whitespace_only_returns_empty_report(self):
        report = audit_text("   \n\n\t  ")
        self.assertEqual(report.documents_scanned, 0)

    def test_malformed_json_returns_error_not_crash(self):
        """Malformed JSON must return a parse error, never raise."""
        report = audit_text("{not valid json")
        self.assertGreater(len(report.errors), 0)
        self.assertIn("parse error", report.errors[0])

    def test_non_workload_kind_skipped(self):
        """A Service manifest is not a workload — no findings expected."""
        svc_yaml = """
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: myapp
  ports:
    - port: 80
"""
        report = audit_text(svc_yaml)
        self.assertEqual(report.workloads_scanned, 0)
        self.assertEqual(report.findings, [])

    def test_document_with_missing_metadata(self):
        """A workload with no metadata should not crash; name defaults."""
        pod_yaml = """
kind: Pod
spec:
  containers:
    - name: c
      image: nginx:latest
"""
        report = audit_text(pod_yaml)
        self.assertEqual(report.workloads_scanned, 1)
        self.assertFalse(any(e for e in report.errors))

    def test_empty_containers_list(self):
        """Pod with an empty containers list should not crash."""
        pod_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: empty
spec:
  containers: []
"""
        report = audit_text(pod_yaml)
        self.assertEqual(report.workloads_scanned, 1)
        # No containers means no per-container findings; should not error.
        self.assertEqual(report.errors, [])

    def test_load_documents_empty_string(self):
        docs = load_documents("")
        self.assertEqual(docs, [])

    def test_load_documents_separator_only(self):
        """A file containing only '---' separators should yield no documents."""
        docs = load_documents("---\n---\n---\n")
        self.assertEqual(docs, [])

    def test_counts_all_severities_present(self):
        """counts property must always return all severity keys even if 0."""
        report = audit_text("")
        counts = report.counts
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn(sev, counts)
            self.assertEqual(counts[sev], 0)

    def test_to_dict_round_trip(self):
        """to_dict() must be JSON-serialisable."""
        from k8saudit import audit_text as at
        report = at("""
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
    - name: c
      image: alpine:latest
""")
        d = report.to_dict()
        serialised = json.dumps(d)  # must not raise
        back = json.loads(serialised)
        self.assertIn("findings", back)


class TestCliErrorPaths(unittest.TestCase):
    """CLI returns non-zero and prints to stderr on bad input."""

    def test_missing_file_exits_2(self):
        """Scanning a file that does not exist must exit with code 2."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            rc = main(["scan", "/nonexistent/path/that/cannot/exist.yaml"])
        self.assertEqual(rc, 2)
        self.assertIn("error", stderr_buf.getvalue().lower())

    def test_no_subcommand_exits_2(self):
        """Calling with no subcommand must exit with 2 and print usage."""
        # main() returns 2 when args.command != "scan"
        rc = main([])
        self.assertEqual(rc, 2)

    def test_directory_path_exits_2(self):
        """Passing a directory instead of a file must exit with 2."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            rc = main(["scan", os.path.dirname(__file__)])
        self.assertEqual(rc, 2)
        self.assertIn("error", stderr_buf.getvalue().lower())

    def test_scan_empty_file_no_crash(self):
        """An empty manifest file should produce a clean 0 exit, no crash."""
        path = os.path.join(os.path.dirname(__file__), "_tmp_empty.yaml")
        open(path, "w", encoding="utf-8").close()
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path])
            self.assertEqual(rc, 0)
        finally:
            os.remove(path)

    def test_scan_malformed_yaml_exits_2(self):
        """Malformed JSON input via file should exit 2 (parse error reported)."""
        path = os.path.join(os.path.dirname(__file__), "_tmp_bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{this is not valid json at all !!!")
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", path, "--format", "json"])
            self.assertEqual(rc, 2)
            data = json.loads(buf.getvalue())
            self.assertGreater(len(data["errors"]), 0)
        finally:
            os.remove(path)

    def test_write_to_output_file(self):
        """--output flag should write the report and return appropriate exit code."""
        src = os.path.join(os.path.dirname(__file__), "_tmp_src.yaml")
        out = os.path.join(os.path.dirname(__file__), "_tmp_out.json")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("")
        try:
            stderr_buf = io.StringIO()
            with redirect_stderr(stderr_buf):
                rc = main(["scan", src, "--format", "json", "--output", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(out))
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
        finally:
            for p in (src, out):
                if os.path.exists(p):
                    os.remove(p)


class TestWebhook(unittest.TestCase):
    """Webhook forwarder input validation."""

    def _run_webhook(self, argv, stdin_text=""):
        """Run webhook main() capturing stderr, with simulated stdin."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "webhook",
            os.path.join(os.path.dirname(__file__), "..", "integrations", "webhook.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        old_argv = sys.argv
        old_stdin = sys.stdin
        stderr_buf = io.StringIO()
        try:
            sys.argv = ["webhook"] + argv
            sys.stdin = io.StringIO(stdin_text)
            with redirect_stderr(stderr_buf):
                rc = mod.main()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
        return rc, stderr_buf.getvalue()

    def test_bad_url_scheme_exits_2(self):
        rc, err = self._run_webhook(["--url", "ftp://example.com"], '{"ok": true}')
        self.assertEqual(rc, 2)
        self.assertIn("http", err)

    def test_empty_stdin_exits_2(self):
        rc, err = self._run_webhook(["--url", "https://example.com"], "")
        self.assertEqual(rc, 2)
        self.assertIn("stdin", err)

    def test_invalid_json_stdin_exits_2(self):
        rc, err = self._run_webhook(["--url", "https://example.com"], "not json at all")
        self.assertEqual(rc, 2)
        self.assertIn("json", err.lower())

    def test_bad_header_format_exits_2(self):
        rc, err = self._run_webhook(
            ["--url", "https://example.com", "--header", "no-colon-here"],
            '{"findings": []}',
        )
        self.assertEqual(rc, 2)
        self.assertIn("Key: Value", err)

    def test_invalid_timeout_exits_2(self):
        rc, err = self._run_webhook(
            ["--url", "https://example.com", "--timeout", "0"],
            '{"findings": []}',
        )
        self.assertEqual(rc, 2)
        self.assertIn("timeout", err.lower())


if __name__ == "__main__":
    unittest.main()
