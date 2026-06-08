"""K8SAUDIT - Audit Kubernetes manifests against CIS-style security rules.

Defensive analysis tool. Operates only on manifest files you provide.
No cluster access, no network, standard library only.
"""
from .core import (
    Finding,
    AuditReport,
    audit_documents,
    audit_text,
    load_documents,
    RULES,
    SEVERITY_ORDER,
)

TOOL_NAME = "k8saudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "AuditReport",
    "audit_documents",
    "audit_text",
    "load_documents",
    "RULES",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
