import type { FindingSeverity, ScanReport } from "./types.js";

const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  high: "🔴 high",
  medium: "🟠 medium",
  low: "🟡 low",
  info: "ℹ️  info"
};
const SEVERITY_RANK: Record<FindingSeverity, number> = { high: 0, medium: 1, low: 2, info: 3 };

export function toMarkdown(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(report.ok ? `# K8s RBAC over-scope scan ✅` : `# K8s RBAC over-scope scan ❌`);
  lines.push(``);
  lines.push(`Generated: \`${report.generatedAt}\``);
  lines.push(``);
  lines.push(
    `- Files: ${report.files} · Documents: ${report.documents} · Roles+ClusterRoles: ${report.rolesScanned} · Bindings: ${report.bindingsScanned}`
  );
  if (report.findings.length === 0) {
    lines.push(``);
    lines.push(`No over-scope findings.`);
    return lines.join("\n");
  }
  const ranked = [...report.findings].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.source.localeCompare(b.source)
  );
  lines.push(``);
  lines.push(`## Findings (${ranked.length})`);
  lines.push(``);
  lines.push(`| severity | code | kind | resource | message |`);
  lines.push(`|---|---|---|---|---|`);
  for (const f of ranked) {
    const resource = [f.namespace, f.name].filter(Boolean).join("/") || f.name;
    const ruleNote = f.ruleIndex !== undefined ? ` (rule #${f.ruleIndex})` : "";
    lines.push(
      `| ${SEVERITY_LABEL[f.severity]} | \`${f.code}\` | ${f.kind} | \`${resource}\`${ruleNote} | ${f.message} |`
    );
  }
  return lines.join("\n");
}

export function toSummary(report: ScanReport): string {
  const counts: Record<FindingSeverity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.findings) counts[f.severity] += 1;
  return `${report.rolesScanned} roles · ${report.bindingsScanned} bindings · ${counts.high} high · ${counts.medium} medium (${report.ok ? "ok" : "fail"})`;
}
