// Find over-scoped RBAC in K8s YAML manifests.
// Models the subset of Role / ClusterRole / RoleBinding / ClusterRoleBinding we need.

export type RbacKind = "Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding";

export interface PolicyRule {
  apiGroups?: string[];
  resources?: string[];
  resourceNames?: string[];
  verbs: string[];
  nonResourceURLs?: string[];
}

export interface RbacRole {
  apiVersion: string;
  kind: "Role" | "ClusterRole";
  metadata: { name: string; namespace?: string };
  rules?: PolicyRule[];
}

export interface RoleRef {
  apiGroup: string;
  kind: string;
  name: string;
}

export interface Subject {
  kind: "User" | "Group" | "ServiceAccount";
  name: string;
  namespace?: string;
  apiGroup?: string;
}

export interface RbacBinding {
  apiVersion: string;
  kind: "RoleBinding" | "ClusterRoleBinding";
  metadata: { name: string; namespace?: string };
  roleRef: RoleRef;
  subjects?: Subject[];
}

export type RbacDoc = RbacRole | RbacBinding;

export type FindingSeverity = "high" | "medium" | "low" | "info";

export type FindingCode =
  | "wildcard-verbs"
  | "wildcard-resources"
  | "wildcard-api-groups"
  | "all-three-wildcards"
  | "escalation-verb"
  | "secret-read"
  | "pod-exec"
  | "cluster-admin-binding"
  | "system-masters-binding"
  | "wildcard-nonresource-urls";

export interface Finding {
  code: FindingCode;
  severity: FindingSeverity;
  message: string;
  source: string;
  kind: RbacKind;
  name: string;
  namespace?: string;
  ruleIndex?: number;
}

export interface ScanReport {
  generatedAt: string;
  files: number;
  documents: number;
  rolesScanned: number;
  bindingsScanned: number;
  findings: Finding[];
  ok: boolean;
}

export interface ScanOptions {
  now?: string;
  /** Path-substring skip filter. */
  skip?: string[];
  /** Namespaces considered "system" (cluster-admin bindings there are not flagged high). */
  systemNamespaces?: string[];
}

export const DEFAULT_SYSTEM_NAMESPACES = ["kube-system", "kube-public", "kube-node-lease"];

/** Verbs that allow a principal to escalate beyond its own role. */
export const ESCALATION_VERBS: ReadonlySet<string> = new Set(["escalate", "bind", "impersonate"]);
