// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import { renderHtml } from "./html.ts";
import type { Evidence, Report } from "./types.ts";

export const REPORTS_DIR = "harness-reports";

export interface WrittenReport {
  readonly dir: string;
  readonly json: string;
  readonly markdown: string;
  readonly html: string;
  readonly patch?: string;
}

export const isInside = (root: string, path: string) => {
  const rel = NodePath.relative(NodePath.resolve(root), NodePath.resolve(path));
  return rel === "" || (!rel.startsWith("..") && !NodePath.isAbsolute(rel));
};

// Reports live with the session, never in the inspected project.
export const defaultReportDir = (root: string, sessionCwd: string) =>
  NodePath.join(
    sessionCwd,
    REPORTS_DIR,
    `${NodePath.basename(root)}-${NodeCrypto.createHash("sha256").update(NodePath.resolve(root)).digest("hex").slice(0, 8)}`,
  );

// The last run written to this directory, if it is a readable report.
export function readPreviousReport(outDir: string): Report | undefined {
  try {
    const doc = JSON.parse(NodeFS.readFileSync(NodePath.join(outDir, "report.json"), "utf8"));
    return doc?.schemaVersion === 1 && typeof doc.runId === "string" ? doc : undefined;
  } catch {
    return undefined;
  }
}

// The only write the inspector performs, always outside the inspected project.
export function writeReport(report: Report, outDir: string): WrittenReport {
  if (isInside(report.root, outDir)) {
    throw new Error(
      `report directory ${outDir} is inside the inspected project; choose one outside it`,
    );
  }
  NodeFS.mkdirSync(outDir, { recursive: true });
  const json = NodePath.join(outDir, "report.json");
  const markdown = NodePath.join(outDir, "report.md");
  NodeFS.writeFileSync(json, `${JSON.stringify(report, null, 2)}\n`);
  NodeFS.writeFileSync(markdown, renderMarkdown(report));
  const html = NodePath.join(outDir, "report.html");
  NodeFS.writeFileSync(html, renderHtml(report));
  const patches = report.findings.flatMap((f) => (f.fix.patch ? [f.fix.patch] : []));
  const patchPath = NodePath.join(outDir, "proposed-fixes.patch");
  if (patches.length > 0) {
    NodeFS.writeFileSync(patchPath, `# harness-inspector run ${report.runId}\n${patches.join("")}`);
    return { dir: outDir, json, markdown, html, patch: patchPath };
  }
  NodeFS.rmSync(patchPath, { force: true });
  return { dir: outDir, json, markdown, html };
}

const loc = (e: Evidence) => `\`${e.file}${e.line === undefined ? "" : `:${e.line}`}\``;
const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

export function renderMarkdown(report: Report): string {
  const { inventory: inv } = report;
  const count = (status: string) => report.findings.filter((f) => f.status === status).length;
  const out: Array<string> = [
    "# Harness security inspection",
    "",
    `- Run: \`${report.runId}\``,
    `- Root: \`${report.root}\``,
    `- Generated: ${report.generatedAt} by ${report.tool.name} ${report.tool.version}`,
    `- Scope: ${report.scope}`,
    `- Session mode: ${report.sessionMode}`,
    `- Approval configuration (not effective permissions): ${report.approvalConfig}`,
    `- Files examined: ${inv.filesExamined}`,
    `- Findings: ${count("confirmed")} confirmed, ${count("probable")} probable, ${count("unverifiable")} unverifiable, ${count("mitigated")} mitigated, ${count("dismissed")} dismissed`,
    "",
    ...(report.comparison
      ? [
          `## Compared with run \`${report.comparison.previousRunId}\``,
          "",
          `- New: ${report.comparison.newIds.join(", ") || "none"}`,
          `- No longer detected by its rule (not proof the risk is gone): ${report.comparison.noLongerDetectedIds.join(", ") || "none"}`,
          `- Persisting: ${report.comparison.persisting.map((p) => (p.from === p.to ? `${p.id} (${p.to})` : `${p.id} (${p.from} → ${p.to})`)).join(", ") || "none"}`,
          "",
        ]
      : []),
    "## Rules executed",
    "",
    "| Rule | Checks | Findings |",
    "| --- | --- | --- |",
    ...report.rulesExecuted.map((r) => `| ${r.id} | ${cell(r.title)} | ${r.findings} |`),
    "",
    "## Inventory",
    "",
    `- Agents: ${inv.agents.map((a) => a.agent).join(", ") || "none detected"}`,
    `- Instruction files: ${inv.instructionFiles.map((f) => `\`${f}\``).join(", ") || "none"}`,
    `- Skills: ${inv.skills.map((s) => `${s.name} (\`${s.dir}\`)`).join(", ") || "none"}`,
    `- MCP servers: ${inv.mcpServers.map((s) => `${s.name} [${s.transport}, ${s.client}]`).join(", ") || "none"}`,
    `- Permission settings: ${inv.permissions.map((p) => `${p.key}=${p.value} (\`${p.file}\`)`).join(", ") || "none"}`,
    `- CI workflows running agents: ${
      inv.workflows
        .filter((w) => w.agentSteps.length || w.reusableCalls.length)
        .map((w) => `\`${w.file}\` (${w.triggers.join(", ")})`)
        .join(", ") || "none"
    }`,
    `- Credential references (names only): ${[...new Set(inv.credentialRefs.map((r) => r.name))].join(", ") || "none"}`,
    "",
    "### Not verified",
    "",
    ...inv.notVerified.map((n) => `- ${n}`),
    "",
    "## Risk path map",
    "",
    "`observed` = read from a file, `inferred` = convention or naming, `unknown` = not available.",
    "",
    "| From | Relation | To | Basis |",
    "| --- | --- | --- | --- |",
    ...report.paths.map(
      (e) => `| ${cell(e.from)} | ${cell(e.relation)} | ${cell(e.to)} | ${e.basis} |`,
    ),
    "",
    "## Findings",
    "",
  ];
  if (report.findings.length === 0)
    out.push("No rule matched. This is not proof that the harness is safe.", "");
  for (const f of report.findings) {
    out.push(
      `### ${f.id} · ${f.status.toUpperCase()} · ${f.title}`,
      "",
      `- Surface: ${f.surface} · Category: ${f.category} · OWASP Agentic: ${f.owasp.join(", ")}`,
      "- Evidence:",
      ...f.evidence.map((e) => `  - ${loc(e)} ${e.detail}`),
      "- Preconditions:",
      ...f.preconditions.map((p) => `  - ${p}`),
      `- Possible impact: ${f.impact}`,
      `- Proposed fix: ${f.fix.summary}`,
      `- How to verify the fix: ${f.verification}`,
      "- Limitations:",
      ...f.limitations.map((l) => `  - ${l}`),
      "",
    );
    if (f.fix.patch) out.push("```diff", f.fix.patch.trimEnd(), "```", "");
  }
  out.push("## Limitations", "", ...report.limitations.map((l) => `- ${l}`), "");
  return out.join("\n");
}
