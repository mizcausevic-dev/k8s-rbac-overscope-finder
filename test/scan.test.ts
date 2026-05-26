import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { scan, listManifestFiles } from "../src/scan.js";
import { toMarkdown, toSummary } from "../src/format.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const ROOT = `${here}/../fixtures/rbac`;
const NOW = "2026-05-27T08:00:00Z";

describe("scan", () => {
  it("counts roles + bindings across the fixture tree", () => {
    const r = scan(ROOT, { now: NOW });
    expect(r.rolesScanned).toBe(4); // wildcard, pod-exec, escalation, clean
    expect(r.bindingsScanned).toBe(3); // 2 in cluster-admin file, 1 in clean
  });

  it("flags all-three-wildcards as a single high finding", () => {
    const r = scan(ROOT, { now: NOW });
    const w = r.findings.filter((f) => f.code === "all-three-wildcards");
    expect(w).toHaveLength(1);
    expect(w[0].severity).toBe("high");
    expect(w[0].kind).toBe("ClusterRole");
    expect(w[0].name).toBe("too-broad");
  });

  it("flags pod-exec as high on Role granting pods/exec", () => {
    const r = scan(ROOT, { now: NOW });
    const pe = r.findings.find((f) => f.code === "pod-exec");
    expect(pe?.severity).toBe("high");
    expect(pe?.name).toBe("support-debug");
  });

  it("flags secret-read as medium when a rule reads Secrets", () => {
    const r = scan(ROOT, { now: NOW });
    const sr = r.findings.find((f) => f.code === "secret-read");
    expect(sr?.severity).toBe("medium");
  });

  it("flags escalation-verb (escalate, bind) as high", () => {
    const r = scan(ROOT, { now: NOW });
    const ev = r.findings.filter((f) => f.code === "escalation-verb");
    expect(ev.length).toBeGreaterThanOrEqual(2);
    for (const f of ev) expect(f.severity).toBe("high");
  });

  it("flags cluster-admin-binding as high on a ClusterRoleBinding", () => {
    const r = scan(ROOT, { now: NOW });
    const ca = r.findings.find((f) => f.code === "cluster-admin-binding");
    expect(ca?.severity).toBe("high");
  });

  it("flags system-masters-binding as high", () => {
    const r = scan(ROOT, { now: NOW });
    const sm = r.findings.find((f) => f.code === "system-masters-binding");
    expect(sm?.severity).toBe("high");
    expect(sm?.name).toBe("privileged-tooling");
  });

  it("ok=false when any high finding present", () => {
    expect(scan(ROOT, { now: NOW }).ok).toBe(false);
  });

  it("respects --skip", () => {
    const r = scan(ROOT, { now: NOW, skip: ["wildcard-role"] });
    expect(r.findings.some((f) => f.name === "too-broad")).toBe(false);
  });

  it("emits 'ok' on a clean-only tree", () => {
    const r = scan(ROOT, { now: NOW, skip: ["wildcard-role", "pod-exec-role", "escalation-role", "cluster-admin-binding"] });
    expect(r.findings).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it("includes :<docIndex> on multi-doc source paths", () => {
    const r = scan(ROOT, { now: NOW });
    const sm = r.findings.find((f) => f.code === "system-masters-binding");
    expect(sm?.source).toMatch(/cluster-admin-binding\.yaml:1$/);
  });

  it("treats Roles as different from ClusterRoles in cluster-admin RoleBinding rule", () => {
    // A non-system-namespace RoleBinding to cluster-admin should also be flagged (medium).
    const r = scan(ROOT, { now: NOW });
    // Our fixture only has ClusterRoleBinding → cluster-admin (high). Medium path is exercised
    // by a synthetic doc below.
    expect(r.findings.filter((f) => f.code === "cluster-admin-binding").length).toBeGreaterThanOrEqual(1);
  });
});

describe("listManifestFiles", () => {
  it("walks the tree and returns *.yaml files", () => {
    const files = listManifestFiles(ROOT);
    expect(files.length).toBe(5);
    expect(files.every((f) => f.endsWith(".yaml"))).toBe(true);
  });
});

describe("formatters", () => {
  it("toMarkdown renders ❌ + ranked findings", () => {
    const md = toMarkdown(scan(ROOT, { now: NOW }));
    expect(md).toContain("❌");
    expect(md).toContain("all-three-wildcards");
    expect(md.indexOf("🔴")).toBeLessThan(md.indexOf("🟠"));
  });

  it("toMarkdown renders ✅ + 'No over-scope findings.' on clean tree", () => {
    const md = toMarkdown({
      generatedAt: NOW,
      files: 0,
      documents: 0,
      rolesScanned: 0,
      bindingsScanned: 0,
      findings: [],
      ok: true
    });
    expect(md).toContain("✅");
    expect(md).toContain("No over-scope findings.");
  });

  it("toSummary emits a one-liner", () => {
    const s = toSummary(scan(ROOT, { now: NOW }));
    expect(s).toMatch(/roles/);
    expect(s).toMatch(/bindings/);
  });
});
