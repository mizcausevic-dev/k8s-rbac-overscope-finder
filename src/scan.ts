import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { parseAllDocuments } from "yaml";

import {
  DEFAULT_SYSTEM_NAMESPACES,
  ESCALATION_VERBS,
  type Finding,
  type FindingCode,
  type FindingSeverity,
  type PolicyRule,
  type RbacBinding,
  type RbacDoc,
  type RbacKind,
  type RbacRole,
  type ScanOptions,
  type ScanReport,
  type Subject
} from "./types.js";

const RBAC_KINDS: ReadonlySet<RbacKind> = new Set(["Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"]);

export function listManifestFiles(root: string, skip: string[] = []): string[] {
  const out: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (skip.some((s) => full.includes(s))) continue;
      if (st.isDirectory()) visit(full);
      else if (/\.ya?ml$/i.test(entry)) out.push(full);
    }
  };
  visit(root);
  return out.sort();
}

function hasWildcard(arr: string[] | undefined): boolean {
  return !!arr && arr.includes("*");
}

function isRole(doc: RbacDoc): doc is RbacRole {
  return doc.kind === "Role" || doc.kind === "ClusterRole";
}
function isBinding(doc: RbacDoc): doc is RbacBinding {
  return doc.kind === "RoleBinding" || doc.kind === "ClusterRoleBinding";
}

function ruleFindings(role: RbacRole, source: string): Finding[] {
  const out: Finding[] = [];
  const base = (code: FindingCode, severity: FindingSeverity, message: string, ruleIndex: number): Finding => {
    const f: Finding = {
      code,
      severity,
      message,
      source,
      kind: role.kind,
      name: role.metadata.name,
      ruleIndex
    };
    if (role.metadata.namespace) f.namespace = role.metadata.namespace;
    return f;
  };

  for (let i = 0; i < (role.rules ?? []).length; i++) {
    const rule = role.rules![i];
    const wv = hasWildcard(rule.verbs);
    const wr = hasWildcard(rule.resources);
    const wg = hasWildcard(rule.apiGroups);

    if (wv && wr && wg) {
      out.push(base("all-three-wildcards", "high", `Rule grants verbs=*, resources=*, apiGroups=* — equivalent to cluster-admin within this scope.`, i));
    } else {
      if (wv) out.push(base("wildcard-verbs", "high", `Rule grants verbs=* (any action).`, i));
      if (wr) out.push(base("wildcard-resources", "medium", `Rule grants resources=*.`, i));
      if (wg) out.push(base("wildcard-api-groups", "medium", `Rule grants apiGroups=*.`, i));
    }

    for (const verb of rule.verbs ?? []) {
      if (ESCALATION_VERBS.has(verb)) {
        out.push(base("escalation-verb", "high", `Rule grants the privileged verb "${verb}".`, i));
      }
    }

    if ((rule.resources ?? []).includes("secrets") && (rule.verbs ?? []).some((v) => ["get", "list", "watch", "*"].includes(v))) {
      out.push(base("secret-read", "medium", `Rule allows reading Kubernetes Secrets.`, i));
    }

    if (
      (rule.resources ?? []).some((r) => r === "pods/exec" || r === "pods/portforward" || r === "pods/attach")
    ) {
      out.push(base("pod-exec", "high", `Rule allows pod exec / portforward / attach — full container shell access.`, i));
    }

    if ((rule.nonResourceURLs ?? []).includes("*")) {
      out.push(base("wildcard-nonresource-urls", "medium", `Rule grants nonResourceURLs=*.`, i));
    }
  }
  return out;
}

function bindingFindings(b: RbacBinding, source: string, systemNs: ReadonlySet<string>): Finding[] {
  const out: Finding[] = [];
  const subjects: Subject[] = b.subjects ?? [];
  const refName = b.roleRef?.name;
  const isClusterAdminRef = b.roleRef?.kind === "ClusterRole" && refName === "cluster-admin";
  const ns = b.metadata.namespace;
  const isSystem = ns !== undefined && systemNs.has(ns);

  const base = (code: FindingCode, severity: FindingSeverity, message: string): Finding => {
    const f: Finding = { code, severity, message, source, kind: b.kind, name: b.metadata.name };
    if (b.metadata.namespace) f.namespace = b.metadata.namespace;
    return f;
  };

  if (isClusterAdminRef && (b.kind === "ClusterRoleBinding" || !isSystem)) {
    out.push(
      base(
        "cluster-admin-binding",
        b.kind === "ClusterRoleBinding" ? "high" : "medium",
        `${b.kind} grants the cluster-admin ClusterRole to ${subjects.length} subject(s).`
      )
    );
  }

  if (subjects.some((s) => s.kind === "Group" && s.name === "system:masters")) {
    out.push(
      base(
        "system-masters-binding",
        "high",
        `Binding targets the system:masters group — equivalent to root on the cluster.`
      )
    );
  }
  return out;
}

export function scan(root: string, opts: ScanOptions = {}): ScanReport {
  const generatedAt = opts.now ?? new Date().toISOString();
  const files = listManifestFiles(root, opts.skip);
  const systemNs = new Set(opts.systemNamespaces ?? DEFAULT_SYSTEM_NAMESPACES);
  const findings: Finding[] = [];
  let documents = 0;
  let rolesScanned = 0;
  let bindingsScanned = 0;

  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const parsed = parseAllDocuments(text);
    parsed.forEach((d, idx) => {
      const json = d.toJSON() as RbacDoc | null;
      if (!json || typeof json !== "object") return;
      documents += 1;
      if (!RBAC_KINDS.has(json.kind as RbacKind)) return;

      const source = parsed.length > 1 ? `${file}:${idx}` : file;
      if (isRole(json)) {
        rolesScanned += 1;
        findings.push(...ruleFindings(json, source));
      } else if (isBinding(json)) {
        bindingsScanned += 1;
        findings.push(...bindingFindings(json, source, systemNs));
      }
    });
  }

  return {
    generatedAt,
    files: files.length,
    documents,
    rolesScanned,
    bindingsScanned,
    findings,
    ok: !findings.some((f) => f.severity === "high")
  };
}

export function rulesFor(role: RbacRole): PolicyRule[] {
  return role.rules ?? [];
}
