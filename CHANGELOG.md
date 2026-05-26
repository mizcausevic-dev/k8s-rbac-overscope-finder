# Changelog

## v0.1.0 — 2026-05-27

- Initial release: scan a directory of Kubernetes YAML manifests for over-scoped RBAC.
- 10 finding codes covering wildcard verbs / resources / apiGroups / nonResourceURLs, escalation verbs (escalate / bind / impersonate), pod-exec / pod-portforward / pod-attach, Secret-read rules, cluster-admin bindings, system:masters group bindings.
- Library API: `scan(root, opts)` → `ScanReport`; `listManifestFiles`, `rulesFor` helpers; `ESCALATION_VERBS`, `DEFAULT_SYSTEM_NAMESPACES` exports.
- Formatters: `toMarkdown(report)` (severity-ranked) and `toSummary(report)`.
- CLI: `k8s-rbac-overscope-finder <manifests-dir>` with `--format json|markdown|summary`, `--skip path,path`, `--system-namespaces ns,ns`, `--fail-on-high`, `--out FILE`.
- Multi-document YAML aware (`---` separator). Uses `yaml` (eemeli/yaml) for full structural parsing of Role / ClusterRole / RoleBinding / ClusterRoleBinding documents.
- Lane #3 (Kubernetes control planes), sibling of `k8s-deprecated-api-scanner`.
- Node 20/22 CI (lint, typecheck, coverage, build, demo, `npm audit`), AGPL-3.0-or-later, Dependabot.
