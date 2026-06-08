# Demo 01 - Basic manifest audit

This demo audits a deliberately insecure Kubernetes Deployment so you can see
K8SAUDIT detect a realistic spread of misconfigurations.

## Input

`insecure-deployment.yaml` is a Deployment that an engineer might hastily ship.
It contains several CIS-style violations on purpose:

- Runs a **privileged** container (K8S-001)
- No `runAsNonRoot` and `runAsUser: 0` (K8S-002)
- `allowPrivilegeEscalation` not disabled (K8S-003)
- Writable root filesystem (K8S-004)
- Capabilities not dropped + adds `SYS_ADMIN`/`NET_ADMIN` (K8S-005, K8S-006)
- `hostNetwork` / `hostPID` enabled (K8S-007)
- Mounts a `hostPath` volume at `/` (K8S-008)
- Uses the `:latest` image tag (K8S-009)
- No CPU/memory limits (K8S-010)
- Service account token auto-mounted (K8S-011)
- A plaintext password in an env var (K8S-012)

## Run it

```sh
# Human-readable table (default)
python -m k8saudit scan demos/01-basic/insecure-deployment.yaml

# Machine-readable JSON for CI pipelines
python -m k8saudit scan demos/01-basic/insecure-deployment.yaml --format json

# Shareable self-contained HTML report (the tool's UI)
python -m k8saudit scan demos/01-basic/insecure-deployment.yaml \
    --format html -o report.html

# Gate a pipeline on high-severity issues only
python -m k8saudit scan demos/01-basic/insecure-deployment.yaml --min-severity HIGH
```

## Exit codes

- `0` - no findings (clean)
- `1` - findings present (fail the build)
- `2` - parse/IO error

The non-zero exit on findings lets you drop K8SAUDIT straight into CI.
