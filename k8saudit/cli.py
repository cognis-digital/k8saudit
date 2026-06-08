"""Command-line interface for K8SAUDIT."""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import AuditReport, SEVERITY_ORDER, audit_text

_SEV_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#374151",
}


def _read_inputs(paths: List[str]) -> str:
    if not paths or paths == ["-"]:
        return sys.stdin.read()
    chunks = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            chunks.append(fh.read())
    return "\n---\n".join(chunks)


def _render_table(report: AuditReport) -> str:
    lines = []
    lines.append("%s %s" % (TOOL_NAME, TOOL_VERSION))
    lines.append("docs scanned: %d   workloads: %d" % (
        report.documents_scanned, report.workloads_scanned))
    c = report.counts
    lines.append("findings: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d" % (
        c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
    lines.append("")
    if not report.findings:
        lines.append("No findings. Manifests pass all checks.")
    else:
        header = "%-9s %-8s %-14s %-22s %-12s %s" % (
            "SEVERITY", "RULE", "KIND", "NAME", "CONTAINER", "DETAIL")
        lines.append(header)
        lines.append("-" * len(header))
        for f in report.findings:
            lines.append("%-9s %-8s %-14s %-22s %-12s %s" % (
                f.severity, f.rule_id, f.kind[:14], f.name[:22],
                (f.container or "-")[:12], f.detail))
    if report.errors:
        lines.append("")
        lines.append("errors:")
        for e in report.errors:
            lines.append("  ! " + e)
    return "\n".join(lines)


def _render_html(report: AuditReport) -> str:
    c = report.counts
    e = html.escape
    rows = []
    for f in report.findings:
        color = _SEV_COLORS.get(f.severity, "#374151")
        rows.append(
            "<tr>"
            "<td><span class='sev' style='background:%s'>%s</span></td>"
            "<td class='mono'>%s</td><td>%s</td><td class='mono'>%s</td>"
            "<td class='mono'>%s</td><td>%s</td><td class='rem'>%s</td>"
            "</tr>" % (
                color, e(f.severity), e(f.rule_id), e(f.title),
                e("%s/%s" % (f.kind, f.name)), e(f.container or "-"),
                e(f.detail), e(f.remediation))
        )
    if not rows:
        rows.append("<tr><td colspan='7' class='ok'>No findings. Manifests pass all checks.</td></tr>")
    err_html = ""
    if report.errors:
        items = "".join("<li>%s</li>" % e(x) for x in report.errors)
        err_html = "<div class='errbox'><h3>Errors</h3><ul>%s</ul></div>" % items
    summary_cells = "".join(
        "<div class='card' style='border-color:%s'><div class='num'>%d</div>"
        "<div class='lab'>%s</div></div>" % (_SEV_COLORS[s], c[s], s)
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>K8SAUDIT Report</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:#94a3b8;font-size:13px;margin-bottom:22px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:26px}
.card{flex:1;min-width:120px;background:#1e293b;border-left:5px solid #334155;border-radius:8px;padding:14px 16px}
.card .num{font-size:28px;font-weight:700}
.card .lab{font-size:12px;letter-spacing:.08em;color:#94a3b8}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #334155;vertical-align:top}
th{background:#0b1220;color:#94a3b8;text-transform:uppercase;font-size:11px;letter-spacing:.06em}
tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:700}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#cbd5e1}
.rem{color:#94a3b8;font-size:12px}
.ok{text-align:center;color:#4ade80;padding:24px;font-size:15px}
.errbox{margin-top:22px;background:#3f1d1d;border-radius:8px;padding:12px 16px}
.errbox h3{margin:0 0 6px;font-size:14px}
footer{margin-top:26px;color:#64748b;font-size:12px}
</style></head><body><div class="wrap">
<h1>K8SAUDIT Security Report</h1>
<div class="sub">%(tool)s %(ver)s &middot; %(docs)d document(s), %(wl)d workload(s) scanned</div>
<div class="cards">%(cards)s</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Resource</th>
<th>Container</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>%(rows)s</tbody></table>
%(errors)s
<footer>Defensive static analysis of Kubernetes manifests. CIS-style rules. No cluster access.</footer>
</div></body></html>""" % {
        "tool": e(TOOL_NAME), "ver": e(TOOL_VERSION),
        "docs": report.documents_scanned, "wl": report.workloads_scanned,
        "cards": summary_cells, "rows": "".join(rows), "errors": err_html,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Audit Kubernetes manifests against CIS-style security rules.")
    p.add_argument("--version", action="version",
                   version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan manifest file(s) for security issues.")
    scan.add_argument("paths", nargs="*", default=["-"],
                      help="Manifest file(s) (YAML/JSON). Use '-' or omit for stdin.")
    scan.add_argument("--format", choices=["table", "json", "html"], default="table",
                      help="Output format (default: table).")
    scan.add_argument("-o", "--output", help="Write report to a file instead of stdout.")
    scan.add_argument("--min-severity", choices=list(SEVERITY_ORDER),
                      help="Only report findings at or above this severity.")
    return p


def _filter(report: AuditReport, min_sev: Optional[str]) -> AuditReport:
    if not min_sev:
        return report
    threshold = SEVERITY_ORDER[min_sev]
    report.findings = [f for f in report.findings
                       if SEVERITY_ORDER.get(f.severity, 9) <= threshold]
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        text = _read_inputs(args.paths)
    except OSError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    report = audit_text(text)
    report = _filter(report, args.min_severity)

    if args.format == "json":
        rendered = json.dumps(report.to_dict(), indent=2)
    elif args.format == "html":
        rendered = _render_html(report)
    else:
        rendered = _render_table(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        except OSError as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 2
        sys.stderr.write("wrote %s report to %s\n" % (args.format, args.output))
    else:
        print(rendered)

    if report.errors:
        return 2
    return 1 if report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
