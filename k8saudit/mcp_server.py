"""K8SAUDIT MCP server — exposes audit_text() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-k8saudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        sys.stderr.write("Install the MCP extra: pip install 'cognis-k8saudit[mcp]'\n")
        return 1

    from k8saudit.core import audit_text

    app = FastMCP("k8saudit")

    @app.tool()
    def k8saudit_scan(manifest: str) -> str:
        """Audit Kubernetes manifests against CIS-style security rules. Returns JSON findings."""
        if not manifest or not manifest.strip():
            return json.dumps({"error": "manifest text must not be empty"})
        report = audit_text(manifest)
        return json.dumps(report.to_dict(), indent=2)

    app.run()
    return 0
