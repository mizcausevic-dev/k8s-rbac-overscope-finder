# k8s-rbac-overscope-finder

Scan a directory of **Kubernetes YAML manifests** for over-scoped RBAC. Pure offline transform — no cluster access, no `kubectl` required, no admission webhook to install.

Catches the cases security review actually cares about: wildcard verbs, escalation primitives, pod-exec, Secret reads, cluster-admin bindings, and `system:masters` group bindings.

> Status: v0.1.0 — Node 20/22 supported, library + CLI. Lane #3 (Kubernetes control planes).

## What it flags

| Code | Severity | Rule |
|---|---|---|
| `all-three-wildcards` | 🔴 | A single rule grants `verbs=*` + `resources=*` + `apiGroups=*` (equivalent to cluster-admin within its scope). |
| `wildcard-verbs` | 🔴 | A rule grants `verbs: ["*"]`. |
| `escalation-verb` | 🔴 | A rule grants `escalate`, `bind`, or `impersonate`. |
| `pod-exec` | 🔴 | A rule grants `pods/exec` / `pods/portforward` / `pods/attach`. |
| `system-masters-binding` | 🔴 | A binding targets the `system:masters` group (root on the cluster). |
| `cluster-admin-binding` | 🔴 (ClusterRoleBinding) / 🟠 (RoleBinding outside system namespaces) | A binding grants the `cluster-admin` ClusterRole. |
| `wildcard-resources` | 🟠 | `resources: ["*"]`. |
| `wildcard-api-groups` | 🟠 | `apiGroups: ["*"]`. |
| `secret-read` | 🟠 | A rule allows reading Secrets. |
| `wildcard-nonresource-urls` | 🟠 | `nonResourceURLs: ["*"]`. |

## CLI

```
npx k8s-rbac-overscope-finder <manifests-dir>
    [--format json|markdown|summary]
    [--skip path-substring,path-substring]
    [--system-namespaces kube-system,kube-public,kube-node-lease]
    [--fail-on-high]
    [--out FILE]
```

Walks the directory recursively, parses every `*.yaml` / `*.yml` (multi-doc supported), and emits findings.

Exit codes:
- `0` — no high findings (or `--fail-on-high` not set)
- `1` — high finding AND `--fail-on-high` set
- `2` — usage / I/O error

Drop it into CI to gate Helm-chart or manifest PRs before they ship.

## Library

```ts
import { scan, toMarkdown, ESCALATION_VERBS } from "k8s-rbac-overscope-finder";

const report = scan("./manifests");
console.log(report.findings);   // [{ code, severity, kind, name, ruleIndex, … }]
console.log(toMarkdown(report));
```

## Composes with

- [**`k8s-deprecated-api-scanner`**](https://github.com/mizcausevic-dev/k8s-deprecated-api-scanner) — sibling scanner for deprecated `apiVersion` usage. Run both before a K8s upgrade or chart publish.
- [**`governance-disclosure-operator`**](https://github.com/mizcausevic-dev/governance-disclosure-operator), [**`scheduled-audit-operator`**](https://github.com/mizcausevic-dev/scheduled-audit-operator), [**`llm-cost-budget-operator`**](https://github.com/mizcausevic-dev/llm-cost-budget-operator) — operator surfaces. Run this scanner against their Helm `templates/` before publishing.

## Develop

```
npm install
npm run lint && npm run typecheck && npm run coverage && npm run build
npm run demo
```

## License

[AGPL-3.0-or-later](LICENSE)
