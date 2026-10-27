import type { Evidence, Finding, Report, VerificationStatus } from "./types.ts";

// Every string from the inspected project is untrusted: it is escaped here and
// the page carries no script, so it is safe to hand to T3's html_render.
const esc = (value: string) => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const STATUS_COLOR: Record<VerificationStatus, string> = {
  confirmed: "var(--destructive)",
  probable: "var(--warning)",
  unverifiable: "var(--info)",
  mitigated: "var(--success)",
  dismissed: "var(--muted-foreground)",
};

const loc = (e: Evidence) => esc(`${e.file}${e.line === undefined ? "" : `:${e.line}`}`);

const list = (items: ReadonlyArray<string>) =>
  items.length === 0 ? "<span class=m>none</span>" : items.map(esc).join(", ");

function finding(f: Finding): string {
  return `<section class=f>
<div class=h><span class=s style="color:${STATUS_COLOR[f.status]}">${f.status}</span> <code>${esc(f.id)}</code> ${esc(f.title)}</div>
<div class=m>${esc(f.surface)} · ${esc(f.category)} · OWASP ${list(f.owasp)}</div>
<ul>${f.evidence.map((e) => `<li><code>${loc(e)}</code> ${esc(e.detail)}</li>`).join("")}</ul>
<p><b>Preconditions</b> ${f.preconditions.map(esc).join(" ")}</p>
<p><b>Impact</b> ${esc(f.impact)}</p>
<p><b>Fix</b> ${esc(f.fix.summary)}${f.fix.patch ? " Patch in proposed-fixes.patch (not applied)." : ""}</p>
${f.fix.patch ? `<pre>${esc(f.fix.patch.trimEnd())}</pre>` : ""}
<p class=m><b>Verify</b> ${esc(f.verification)}</p>
</section>`;
}

export function renderHtml(report: Report): string {
  const inv = report.inventory;
  const count = (s: VerificationStatus) => report.findings.filter((f) => f.status === s).length;
  const rows: ReadonlyArray<[string, string]> = [
    ["Agents", list(inv.agents.map((a) => a.agent))],
    ["Instruction files", list(inv.instructionFiles)],
    ["Skills", list(inv.skills.map((s) => `${s.name} (${s.dir})`))],
    ["MCP servers", list(inv.mcpServers.map((s) => `${s.name} [${s.transport}, ${s.client}]`))],
    ["Permission settings", list(inv.permissions.map((p) => `${p.key}=${p.value}`))],
    [
      "CI agent workflows",
      list(
        inv.workflows
          .filter((w) => w.agentSteps.length || w.reusableCalls.length)
          .map((w) => w.file),
      ),
    ],
    ["Credential references", list([...new Set(inv.credentialRefs.map((r) => r.name))])],
  ];
  return `<!doctype html>
<html><head><meta charset=utf-8><meta name="harness-run-id" content="${esc(report.runId)}"><title>Harness security inspection ${esc(report.runId)}</title>
<style>
body{font-family:var(--font-sans);margin:0}
code,pre{font-family:var(--font-mono);font-size:12px}
pre{background:var(--code-background);padding:16px;border-radius:var(--radius);overflow-x:auto;white-space:pre}
table{border-collapse:collapse;width:100%;font-size:13px}
td{border-bottom:1px solid var(--border);padding:6px 8px;vertical-align:top}
td:first-child{color:var(--muted-foreground);white-space:nowrap}
.f{border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin:12px 0;font-size:13px}
.h{font-weight:600}.s{text-transform:uppercase;font-size:11px;font-weight:700}
.m{color:var(--muted-foreground)}p{margin:6px 0}ul{margin:6px 0;padding-left:18px}
</style></head><body>
<p><b>${count("confirmed")}</b> confirmed · <b>${count("probable")}</b> probable · <b>${count("unverifiable")}</b> unverifiable · <b>${count("mitigated")}</b> mitigated · <b>${count("dismissed")}</b> dismissed · ${inv.filesExamined} files read, nothing executed</p>
<p class=m>Run <code>${esc(report.runId)}</code> · ${esc(report.generatedAt)}</p>
${report.comparison ? `<p class=m>Compared with run <code>${esc(report.comparison.previousRunId)}</code>: new ${list(report.comparison.newIds)} · no longer detected by its rule (not proof the risk is gone) ${list(report.comparison.noLongerDetectedIds)} · persisting ${list(report.comparison.persisting.map((p) => (p.from === p.to ? `${p.id} (${p.to})` : `${p.id} (${p.from} → ${p.to})`)))}</p>` : ""}
<p class=m>${esc(report.sessionMode)}</p>
<p style="color:var(--warning)"><b>Approval configuration (effective mode not verified)</b> ${esc(report.approvalConfig)}</p>
<p class=m>Rules run: ${report.rulesExecuted.map((r) => `${esc(r.id)} (${r.findings})`).join(", ")}</p>
<table>${rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("")}</table>
${report.findings.map(finding).join("\n")}
<p class=m>Static inspection only; it does not block agent actions. Not verified: ${inv.notVerified.map(esc).join(" ")}</p>
</body></html>
`;
}
