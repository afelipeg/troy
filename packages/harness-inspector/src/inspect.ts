// @effect-diagnostics globalDate:off nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import { discover, type Discovery } from "./discover.ts";
import { ProjectFiles } from "./projectFiles.ts";
import { RULES } from "./rules.ts";
import type { Finding, PathEdge, Report, RunComparison } from "./types.ts";

export const TOOL = { name: "t3-harness-inspector", version: "0.1.0" } as const;

const STATUS_ORDER = {
  confirmed: 0,
  probable: 1,
  unverifiable: 2,
  mitigated: 3,
  dismissed: 4,
} as const;

export function inspect(
  root: string,
  options: {
    readonly now?: Date;
    readonly sessionCwd?: string;
    readonly previous?: Report;
  } = {},
): Report {
  const files = new ProjectFiles(root);
  const discovery = discover(files);
  const rulesExecuted: Array<Report["rulesExecuted"][number]> = [];
  const findings: Array<Finding> = [];
  for (const rule of RULES) {
    const drafts = rule.run(files, discovery);
    rulesExecuted.push({ id: rule.id, title: rule.title, findings: drafts.length });
    for (const draft of drafts) {
      const base = `${rule.id}-${NodeCrypto.createHash("sha256").update(`${rule.id}\0${draft.subject}`).digest("hex").slice(0, 8)}`;
      let id = base;
      for (let n = 2; findings.some((f) => f.id === id); n++) id = `${base}-${n}`;
      findings.push({ id, ...draft });
    }
  }
  findings.sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);

  const previous = options.previous?.root === files.root ? options.previous : undefined;
  const startedAt = options.now ?? new Date();
  return {
    schemaVersion: 1,
    runId: `${startedAt.toISOString().replace(/[-:.]/g, "")}-${NodeCrypto.randomBytes(3).toString("hex")}`,
    tool: TOOL,
    generatedAt: startedAt.toISOString(),
    root: files.root,
    scope: "Files under the selected root only. Read-only; nothing was executed or contacted.",
    sessionMode: sessionModeOf(files.root, options.sessionCwd),
    approvalConfig: approvalConfigOf(options.sessionCwd),
    rulesExecuted,
    inventory: discovery.inventory,
    paths: buildPaths(discovery),
    findings,
    ...(previous ? { comparison: compare(previous, findings) } : {}),
    limitations: [
      "Static inspection: it does not observe, block, or protect agent actions at runtime.",
      "Rules cover specific, listed patterns; absence of findings is not proof of safety.",
      '"confirmed" means every precondition the rule checks was observed in files, not that it was exploited.',
    ],
  };
}

// Instruction files each agent loads by convention.
const CONVENTIONS: ReadonlyArray<{ agent: string; file: RegExp; skills: RegExp }> = [
  { agent: "Claude Code", file: /(^|\/)CLAUDE(\.local)?\.md$/, skills: /^\.claude\/skills\// },
  { agent: "Codex", file: /(^|\/)AGENTS\.md$/, skills: /^\.(agents|codex)\/skills\// },
  { agent: "Gemini CLI", file: /(^|\/)GEMINI\.md$/, skills: /^\.gemini\/skills\// },
  { agent: "Cursor", file: /^\.cursorrules$|^\.cursor\/rules\//, skills: /^\.cursor\/skills\// },
  { agent: "GitHub Copilot", file: /copilot-instructions\.md$/, skills: /^\.github\/skills\// },
];

function buildPaths({ inventory }: Discovery): Array<PathEdge> {
  const edges: Array<PathEdge> = [];
  const present = new Set(inventory.agents.map((a) => a.agent));
  for (const c of CONVENTIONS) {
    if (!present.has(c.agent)) continue;
    for (const file of inventory.instructionFiles.filter((f) => c.file.test(f))) {
      edges.push({
        from: c.agent,
        to: file,
        relation: "loads instructions (by convention)",
        basis: "inferred",
      });
    }
    for (const skill of inventory.skills.filter((s) => c.skills.test(`${s.dir}/`))) {
      edges.push({
        from: c.agent,
        to: `skill:${skill.name}`,
        relation: "may load skill (by convention)",
        basis: "inferred",
      });
    }
  }
  for (const s of inventory.mcpServers) {
    const node = `mcp:${s.name}`;
    const evidence = {
      file: s.file,
      ...(s.line === undefined ? {} : { line: s.line }),
      detail: "declared",
    };
    edges.push({
      from: s.client,
      to: node,
      relation: "configures MCP server",
      basis: "observed",
      evidence,
    });
    if (s.transport === "http") {
      edges.push({
        from: node,
        to: `remote:${hostOf(s.url)}`,
        relation: "sends tool calls to",
        basis: "observed",
        evidence,
      });
    } else {
      for (const arg of s.args.filter(
        (a) => a.startsWith("/") || a.startsWith(".") || a.startsWith("~"),
      )) {
        edges.push({
          from: node,
          to: `path:${arg}`,
          relation: "argument (possible resource scope)",
          basis: "observed",
          evidence,
        });
      }
    }
    edges.push({
      from: node,
      to: "tools:not-enumerated",
      relation: "exposes tools",
      basis: "unknown",
    });
  }
  for (const p of inventory.permissions) {
    edges.push({
      from: p.client,
      to: `permission:${p.key}=${p.value}`,
      relation: "runs with",
      basis: "observed",
      evidence: {
        file: p.file,
        ...(p.line === undefined ? {} : { line: p.line }),
        detail: "configured",
      },
    });
  }
  for (const wf of inventory.workflows) {
    for (const step of wf.agentSteps) {
      const node = `ci:${wf.file}#${step.job}`;
      for (const t of wf.triggers) {
        edges.push({ from: `event:${t}`, to: node, relation: "triggers", basis: "observed" });
      }
      edges.push({
        from: node,
        to: `agent:${step.agent}`,
        relation: "runs",
        basis: "observed",
        evidence: {
          file: wf.file,
          ...(step.line === undefined ? {} : { line: step.line }),
          detail: "agent step",
        },
      });
    }
    for (const call of wf.reusableCalls) {
      edges.push({
        from: `ci:${wf.file}#${call.job}`,
        to: `workflow:${call.uses}`,
        relation: "delegates to (contents unknown)",
        basis: "unknown",
      });
    }
  }
  return edges;
}

const hostOf = (url: string | undefined) => {
  try {
    return url ? new URL(url).host : "unknown";
  } catch {
    return "unknown";
  }
};

function sessionModeOf(root: string, sessionCwd: string | undefined): string {
  if (sessionCwd === undefined) return "unknown: no session directory was given";
  const rel = NodePath.relative(root, NodePath.resolve(sessionCwd));
  return rel === "" || !rel.startsWith("..")
    ? "session-inside-target: the agent session's working directory is inside the inspected project. Clients that load project-scoped configuration from the working directory (such as Claude Code's .mcp.json, CLAUDE.md and .claude/skills) may have loaded this project's MCP servers, instructions and skills before or during this inspection."
    : "session-outside-target: the agent session's working directory is outside the inspected project, so configuration a client loads from its working directory did not come from this project. This is not a sandbox: the agent still reads this project's files as untrusted text that can carry prompt injection, user-level configuration and MCP servers still load, and other client behavior was not verified.";
}

function compare(previous: Report, findings: ReadonlyArray<Finding>): RunComparison {
  // The previous report sits in a directory the inspected project can write to,
  // so only well-formed ids and known statuses are carried over.
  const before = new Map(
    (Array.isArray(previous.findings) ? previous.findings : [])
      .filter(
        (f) =>
          /^HI-[A-Z]+-\d{3}-[0-9a-f]{8}(-\d+)?$/.test(String(f?.id)) && f.status in STATUS_ORDER,
      )
      .map((f) => [f.id, f.status]),
  );
  const now = new Set(findings.map((f) => f.id));
  return {
    previousRunId: /^[0-9TZ]+-[0-9a-f]{6}$/.test(previous.runId) ? previous.runId : "unrecognized",
    newIds: findings.filter((f) => !before.has(f.id)).map((f) => f.id),
    noLongerDetectedIds: [...before.keys()].filter((id) => !now.has(id)),
    persisting: findings.flatMap((f) => {
      const from = before.get(f.id);
      return from ? [{ id: f.id, from, to: f.status }] : [];
    }),
  };
}

// Reads only the session's own project, never the inspected one.
function approvalConfigOf(sessionCwd: string | undefined): string {
  if (sessionCwd === undefined)
    return "unknown: no session directory was given. Effective permission mode: not verified.";
  const file = NodePath.join(sessionCwd, ".claude", "settings.json");
  let detected = false;
  try {
    detected =
      JSON.parse(NodeFS.readFileSync(file, "utf8"))?.permissions?.disableBypassPermissionsMode ===
      "disable";
  } catch {
    detected = false;
  }
  return detected
    ? `detected: ${file} sets permissions.disableBypassPermissionsMode = "disable" (a Claude Code setting). Effective permission mode: not verified by the inspector. Evidence: one run in T3 on 2026-10-27 with Claude, where commands and reads outside the session's project asked for approval in Full access while reads inside it and T3's own tools did not. Full access is not equivalent to Supervised.`
    : `none detected in ${file}. Effective permission mode: not verified by the inspector. Evidence: one run in T3 on 2026-10-27 with Claude, where a thread in Full access without this setting ran the audit's commands and reads without approval. A confirmation in chat is not a control.`;
}
