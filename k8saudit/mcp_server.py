"""K8SAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from k8saudit.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-k8saudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-k8saudit[mcp]'")
        return 1
    app = FastMCP("k8saudit")

    @app.tool()
    def k8saudit_scan(target: str) -> str:
        """Audit Kubernetes manifests against CIS-style security rules. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
