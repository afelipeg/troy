#!/usr/bin/env node
// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import { inspect } from "./inspect.ts";
import { defaultReportDir, isInside, readPreviousReport, writeReport } from "./report.ts";

const args = process.argv.slice(2);
const target = args.find((a) => !a.startsWith("--"));
const outFlag = args.indexOf("--out");
if (!target || args.includes("--help")) {
  process.stderr.write("usage: harness-inspector <project-dir> [--out <dir>]\n");
  process.exit(args.includes("--help") ? 0 : 2);
}
const root = NodePath.resolve(target);
if (!NodeFS.statSync(root, { throwIfNoEntry: false })?.isDirectory()) {
  process.stderr.write(`not a directory: ${root}\n`);
  process.exit(2);
}

if (outFlag < 0 && isInside(root, process.cwd())) {
  process.stderr.write(
    `refusing to write reports inside ${root}: run from outside the project or pass --out <dir outside it>\n`,
  );
  process.exit(2);
}
const outDir =
  outFlag >= 0 ? NodePath.resolve(args[outFlag + 1] ?? "") : defaultReportDir(root, process.cwd());
if (isInside(root, outDir)) {
  process.stderr.write(`refusing to write reports inside ${root}: ${outDir}\n`);
  process.exit(2);
}
const previous = readPreviousReport(outDir);
const report = inspect(root, { sessionCwd: process.cwd(), ...(previous ? { previous } : {}) });
const written = writeReport(report, outDir);
const inv = report.inventory;
const lines = [
  `Run ${report.runId}: inspected ${root} (${inv.filesExamined} files, read-only)`,
  `Agents: ${inv.agents.map((a) => a.agent).join(", ") || "none"}`,
  `Session mode: ${report.sessionMode}`,
  `Approval config: ${report.approvalConfig}`,
  `MCP servers: ${inv.mcpServers.length} · skills: ${inv.skills.length} · workflows: ${inv.workflows.length} · permission settings: ${inv.permissions.length}`,
  "Rules executed:",
  ...report.rulesExecuted.map((r) => `  ${r.id}  ${r.findings} finding(s)  ${r.title}`),
  "Findings:",
  ...report.findings.map((f) => {
    const e = f.evidence[1] ?? f.evidence[0];
    return `  [${f.status}] ${f.id} ${f.title}${e ? ` (${e.file}${e.line ? `:${e.line}` : ""})` : ""}`;
  }),
  ...(report.comparison
    ? [
        `Compared with run ${report.comparison.previousRunId}: new ${report.comparison.newIds.length}, no longer detected by its rule (not proof the risk is gone) ${report.comparison.noLongerDetectedIds.join(", ") || "none"}, changed ${
          report.comparison.persisting
            .filter((p) => p.from !== p.to)
            .map((p) => `${p.id} ${p.from}->${p.to}`)
            .join(", ") || "none"
        }`,
      ]
    : []),
  `Reports: ${written.json}`,
  `         ${written.markdown}`,
  `         ${written.html} (static, for html_render)`,
  ...(written.patch ? [`Proposed fixes (not applied): ${written.patch}`] : []),
];
process.stdout.write(`${lines.join("\n")}\n`);
