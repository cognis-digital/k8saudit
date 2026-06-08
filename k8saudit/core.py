"""Core audit engine for K8SAUDIT.

Parses Kubernetes manifests (a tiny dependency-free YAML/JSON multi-doc reader)
and evaluates each workload against CIS-style security rules. All logic is real
and self-contained; no third-party packages and no network.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Kubernetes kinds that embed a pod template / pod spec.
WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "ReplicationController",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    kind: str
    name: str
    namespace: str
    container: Optional[str]
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    documents_scanned: int = 0
    workloads_scanned: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        out = {sev: 0 for sev in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def failed(self) -> bool:
        return bool(self.findings) or bool(self.errors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "documents_scanned": self.documents_scanned,
            "workloads_scanned": self.workloads_scanned,
            "counts": self.counts,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Minimal YAML / JSON multi-document loader (dependency-free).
# Supports the subset of YAML commonly used in k8s manifests: nested maps via
# indentation, block lists with '-', scalars, quoted strings, and 'key: value'.
# JSON input is parsed natively. Documents are separated by '---'.
# ---------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    out = []
    in_s = in_d = False
    for ch in line:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(token: str) -> Any:
    token = token.strip()
    if token == "" or token in ("~", "null", "Null", "NULL"):
        return None
    if (token[0] == '"' and token[-1] == '"') or (token[0] == "'" and token[-1] == "'"):
        return token[1:-1]
    low = token.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in inner.split(",")]
    return token


class _Line:
    __slots__ = ("indent", "text")

    def __init__(self, indent: int, text: str):
        self.indent = indent
        self.text = text


def _parse_block(lines: List[_Line], idx: int, indent: int):
    """Recursively parse a YAML block starting at lines[idx] with given indent.
    Returns (value, next_index)."""
    # Detect list vs map by first significant line at this indent.
    if idx >= len(lines):
        return None, idx
    first = lines[idx]
    if first.text.startswith("- ") or first.text == "-":
        return _parse_list(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_map(lines: List[_Line], idx: int, indent: int):
    result: Dict[str, Any] = {}
    while idx < len(lines):
        line = lines[idx]
        if line.indent < indent:
            break
        if line.indent > indent:
            idx += 1
            continue
        text = line.text
        if ":" not in text:
            idx += 1
            continue
        key, _, rest = text.partition(":")
        key = key.strip().strip('"').strip("'")
        rest = rest.strip()
        if rest:
            result[key] = _scalar(rest)
            idx += 1
        else:
            # Nested block belongs to this key.
            nxt = idx + 1
            if nxt < len(lines) and lines[nxt].indent > indent:
                child_indent = lines[nxt].indent
                value, idx = _parse_block(lines, nxt, child_indent)
                result[key] = value
            elif nxt < len(lines) and lines[nxt].indent == indent and (
                lines[nxt].text.startswith("- ") or lines[nxt].text == "-"
            ):
                # List items at same indent as key (common YAML style).
                value, idx = _parse_list(lines, nxt, indent)
                result[key] = value
            else:
                result[key] = None
                idx = nxt
    return result, idx


def _parse_list(lines: List[_Line], idx: int, indent: int):
    result: List[Any] = []
    while idx < len(lines):
        line = lines[idx]
        if line.indent < indent:
            break
        if line.indent > indent:
            idx += 1
            continue
        if not (line.text.startswith("- ") or line.text == "-"):
            break
        item_text = line.text[1:].lstrip()
        if item_text == "":
            # Block item on following lines.
            nxt = idx + 1
            if nxt < len(lines) and lines[nxt].indent > indent:
                value, idx = _parse_block(lines, nxt, lines[nxt].indent)
                result.append(value)
            else:
                result.append(None)
                idx = nxt
        elif ":" in item_text and not (item_text[0] in "'\""):
            # Inline map start: '- key: val'. Build a synthetic sub-block.
            # The item's own content sits at indent+2 conceptually.
            item_indent = line.indent + 2
            synth = [_Line(item_indent, item_text)]
            j = idx + 1
            while j < len(lines) and lines[j].indent >= item_indent:
                synth.append(lines[j])
                j += 1
            value, _ = _parse_map(synth, 0, item_indent)
            result.append(value)
            idx = j
        else:
            result.append(_scalar(item_text))
            idx += 1
    return result, idx


def _parse_yaml_doc(doc_text: str) -> Any:
    raw_lines: List[_Line] = []
    for raw in doc_text.splitlines():
        stripped = _strip_comment(raw)
        if stripped.strip() == "":
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        raw_lines.append(_Line(indent, stripped.strip() if False else stripped.lstrip(" ")))
    if not raw_lines:
        return None
    base = min(l.indent for l in raw_lines)
    value, _ = _parse_block(raw_lines, 0, base)
    return value


def load_documents(text: str) -> List[Any]:
    """Load one or more YAML/JSON documents from text. Returns list of dicts."""
    text = text.replace("\t", "  ")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            return [d for d in data if d is not None]
        return [data]
    docs: List[Any] = []
    chunk: List[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            doc = _parse_yaml_doc("\n".join(chunk))
            if doc is not None:
                docs.append(doc)
            chunk = []
        else:
            chunk.append(line)
    doc = _parse_yaml_doc("\n".join(chunk))
    if doc is not None:
        docs.append(doc)
    return docs


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------

def _get(d: Any, *path, default=None):
    cur = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = doc.get("kind")
    if kind == "Pod":
        return _get(doc, "spec")
    if kind == "CronJob":
        return _get(doc, "spec", "jobTemplate", "spec", "template", "spec")
    return _get(doc, "spec", "template", "spec")


def _containers(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        items = pod_spec.get(key)
        if isinstance(items, list):
            out.extend([c for c in items if isinstance(c, dict)])
    return out


@dataclass
class _Ctx:
    doc: Dict[str, Any]
    pod_spec: Dict[str, Any]
    kind: str
    name: str
    namespace: str


# A rule is (id, title, severity, remediation, check_fn).
# check_fn(ctx) -> list of (container_name_or_None, detail) tuples for failures.
RuleCheck = Callable[[_Ctx], List[Any]]


def _r_privileged(ctx: _Ctx):
    out = []
    for c in _containers(ctx.pod_spec):
        if _get(c, "securityContext", "privileged") is True:
            out.append((c.get("name"), "securityContext.privileged is true"))
    return out


def _r_root(ctx: _Ctx):
    out = []
    pod_run_as = _get(ctx.pod_spec, "securityContext", "runAsNonRoot")
    for c in _containers(ctx.pod_spec):
        c_nonroot = _get(c, "securityContext", "runAsNonRoot")
        run_as_user = _get(c, "securityContext", "runAsUser")
        if run_as_user == 0:
            out.append((c.get("name"), "runAsUser is 0 (root)"))
        elif c_nonroot is True or pod_run_as is True:
            continue
        elif run_as_user is None:
            out.append((c.get("name"), "runAsNonRoot not set and no non-root runAsUser"))
    return out


def _r_privesc(ctx: _Ctx):
    out = []
    for c in _containers(ctx.pod_spec):
        if _get(c, "securityContext", "allowPrivilegeEscalation") is not False:
            out.append((c.get("name"), "allowPrivilegeEscalation is not set to false"))
    return out


def _r_readonly_fs(ctx: _Ctx):
    out = []
    for c in _containers(ctx.pod_spec):
        if _get(c, "securityContext", "readOnlyRootFilesystem") is not True:
            out.append((c.get("name"), "readOnlyRootFilesystem is not true"))
    return out


def _r_cap_drop_all(ctx: _Ctx):
    out = []
    for c in _containers(ctx.pod_spec):
        drop = _get(c, "securityContext", "capabilities", "drop") or []
        drop_up = {str(x).upper() for x in drop}
        if "ALL" not in drop_up:
            out.append((c.get("name"), "capabilities.drop does not include ALL"))
    return out


def _r_cap_add_dangerous(ctx: _Ctx):
    dangerous = {"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "ALL", "SYS_PTRACE", "SYS_MODULE"}
    out = []
    for c in _containers(ctx.pod_spec):
        add = _get(c, "securityContext", "capabilities", "add") or []
        bad = sorted({str(x).upper() for x in add} & dangerous)
        if bad:
            out.append((c.get("name"), "adds dangerous capabilities: " + ", ".join(bad)))
    return out


def _r_host_namespaces(ctx: _Ctx):
    out = []
    for ns_key, label in (("hostNetwork", "hostNetwork"), ("hostPID", "hostPID"), ("hostIPC", "hostIPC")):
        if ctx.pod_spec.get(ns_key) is True:
            out.append((None, label + " is true (shares node namespace)"))
    return out


def _r_hostpath(ctx: _Ctx):
    out = []
    vols = ctx.pod_spec.get("volumes") or []
    for v in vols:
        if isinstance(v, dict) and isinstance(v.get("hostPath"), dict):
            path = _get(v, "hostPath", "path", default="?")
            out.append((None, "mounts hostPath volume '%s' (%s)" % (v.get("name", "?"), path)))
    return out


def _r_latest_image(ctx: _Ctx):
    out = []
    for c in _containers(ctx.pod_spec):
        img = c.get("image")
        if not isinstance(img, str):
            continue
        tag = img.rsplit("/", 1)[-1]
        if "@sha256:" in img:
            continue
        if ":" not in tag or img.endswith(":latest"):
            out.append((c.get("name"), "image '%s' uses ':latest' or no explicit tag" % img))
    return out


def _r_resource_limits(ctx: _Ctx):
    out = []
    for c in _containers(ctx.pod_spec):
        limits = _get(c, "resources", "limits") or {}
        if not limits.get("cpu") or not limits.get("memory"):
            out.append((c.get("name"), "missing CPU and/or memory resource limits"))
    return out


def _r_default_sa_token(ctx: _Ctx):
    out = []
    pod_mount = ctx.pod_spec.get("automountServiceAccountToken")
    if pod_mount is not False:
        out.append((None, "automountServiceAccountToken not disabled at pod level"))
    return out


def _r_secret_env(ctx: _Ctx):
    suspicious = ("password", "passwd", "secret", "token", "apikey", "api_key", "access_key", "private_key")
    out = []
    for c in _containers(ctx.pod_spec):
        env = c.get("env") or []
        for e in env:
            if not isinstance(e, dict):
                continue
            name = str(e.get("name", "")).lower()
            val = e.get("value")
            if val is not None and any(s in name for s in suspicious):
                out.append((c.get("name"), "env var '%s' has an inline plaintext value (use a Secret)" % e.get("name")))
    return out


RULES = [
    ("K8S-001", "Privileged container", "CRITICAL",
     "Remove securityContext.privileged or set it to false.", _r_privileged),
    ("K8S-002", "Container may run as root", "HIGH",
     "Set securityContext.runAsNonRoot: true and a non-zero runAsUser.", _r_root),
    ("K8S-003", "Privilege escalation allowed", "HIGH",
     "Set securityContext.allowPrivilegeEscalation: false.", _r_privesc),
    ("K8S-004", "Root filesystem is writable", "MEDIUM",
     "Set securityContext.readOnlyRootFilesystem: true.", _r_readonly_fs),
    ("K8S-005", "Capabilities not dropped", "MEDIUM",
     "Set securityContext.capabilities.drop: [ALL].", _r_cap_drop_all),
    ("K8S-006", "Dangerous capabilities added", "HIGH",
     "Remove dangerous Linux capabilities from capabilities.add.", _r_cap_add_dangerous),
    ("K8S-007", "Host namespace shared", "HIGH",
     "Do not set hostNetwork/hostPID/hostIPC to true.", _r_host_namespaces),
    ("K8S-008", "hostPath volume mounted", "HIGH",
     "Avoid hostPath volumes; use PVCs or projected volumes.", _r_hostpath),
    ("K8S-009", "Mutable / latest image tag", "MEDIUM",
     "Pin images to an explicit tag or a sha256 digest.", _r_latest_image),
    ("K8S-010", "Missing resource limits", "LOW",
     "Set resources.limits.cpu and resources.limits.memory.", _r_resource_limits),
    ("K8S-011", "Service account token auto-mounted", "LOW",
     "Set automountServiceAccountToken: false unless the pod calls the API.", _r_default_sa_token),
    ("K8S-012", "Plaintext secret in env", "HIGH",
     "Reference a Secret via valueFrom.secretKeyRef instead of an inline value.", _r_secret_env),
]


def audit_documents(docs: List[Any]) -> AuditReport:
    report = AuditReport()
    report.documents_scanned = len(docs)
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if kind not in WORKLOAD_KINDS:
            continue
        pod_spec = _pod_spec(doc)
        if not isinstance(pod_spec, dict):
            continue
        report.workloads_scanned += 1
        name = _get(doc, "metadata", "name", default="<unnamed>")
        namespace = _get(doc, "metadata", "namespace", default="default")
        ctx = _Ctx(doc=doc, pod_spec=pod_spec, kind=kind, name=name, namespace=namespace)
        for rule_id, title, severity, remediation, check in RULES:
            try:
                hits = check(ctx)
            except Exception as exc:  # rules must never crash the audit
                report.errors.append("rule %s on %s/%s: %s" % (rule_id, kind, name, exc))
                continue
            for container, detail in hits or []:
                report.findings.append(Finding(
                    rule_id=rule_id, title=title, severity=severity,
                    kind=kind, name=name, namespace=namespace,
                    container=container, detail=detail, remediation=remediation,
                ))
    report.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.kind, f.name, f.rule_id))
    return report


def audit_text(text: str) -> AuditReport:
    try:
        docs = load_documents(text)
    except Exception as exc:
        rep = AuditReport()
        rep.errors.append("parse error: %s" % exc)
        return rep
    return audit_documents(docs)
