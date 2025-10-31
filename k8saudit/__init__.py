"""K8SAUDIT — Audit Kubernetes manifests against CIS-style security rules."""
from k8saudit.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
