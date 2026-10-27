// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodePath from "node:path";
import * as Yaml from "yaml";
import type { ProjectFiles } from "./projectFiles.ts";
import type {
  AgentSignal,
  CredentialRef,
  Evidence,
  Inventory,
  McpServer,
  PermissionSetting,
  SkillEntry,
  WorkflowEntry,
} from "./types.ts";

const INSTRUCTION_FILE =
  /(^|\/)(AGENTS\.md|CLAUDE\.md|CLAUDE\.local\.md|GEMINI\.md|\.cursorrules|copilot-instructions\.md)$|^\.cursor\/rules\//;

const AGENT_MARKERS: ReadonlyArray<{ agent: string; match: RegExp }> = [
  { agent: "Claude Code", match: /(^|\/)CLAUDE(\.local)?\.md$|^\.claude\/|^\.mcp\.json$/ },
  { agent: "Codex", match: /(^|\/)AGENTS\.md$|^\.codex\// },
  { agent: "Cursor", match: /^\.cursor\/|^\.cursorrules$/ },
  { agent: "Gemini CLI", match: /(^|\/)GEMINI\.md$|^\.gemini\// },
  { agent: "OpenCode", match: /^opencode\.jsonc?$|^\.opencode\// },
  { agent: "GitHub Copilot", match: /^\.github\/copilot-instructions\.md$|^\.vscode\/mcp\.json$/ },
];

// Config file -> client that loads it, and the key holding its MCP servers.
const MCP_JSON_FILES: ReadonlyArray<{ file: string; client: string; key: string }> = [
  { file: ".mcp.json", client: "Claude Code", key: "mcpServers" },
  { file: ".cursor/mcp.json", client: "Cursor", key: "mcpServers" },
  { file: ".vscode/mcp.json", client: "VS Code / Copilot", key: "servers" },
  { file: ".gemini/settings.json", client: "Gemini CLI", key: "mcpServers" },
  { file: "opencode.json", client: "OpenCode", key: "mcp" },
];

export const AGENT_ACTION =
  /anthropics\/claude-code(-base)?-action|openai\/codex-action|google-github-actions\/run-gemini-cli|google-gemini\/gemini-cli-action|actions\/ai-inference/;
export const AGENT_CLI = /(^|[\s;&|(])(claude|codex|gemini|opencode|cursor-agent)(\s|$)/m;

export type WorkflowDoc = Record<string, unknown>;

export interface Discovery {
  readonly inventory: Inventory;
  readonly workflowDocs: ReadonlyMap<string, WorkflowDoc>;
}

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const strings = (value: unknown): Array<string> =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];

const keysOf = (value: unknown): Array<string> => (isRecord(value) ? Object.keys(value) : []);

export const lineProp = (line: number | undefined): { line?: number } =>
  line === undefined ? {} : { line };

export function discover(files: ProjectFiles): Discovery {
  const notVerified: Array<string> = [
    "User-level agent configuration (~/.claude, ~/.codex, ~/.cursor, ~/.gemini) is outside the selected project and was not read.",
    "Effective GitHub token permissions depend on repository and organization defaults, which are not visible in files.",
    "Tool lists exposed by MCP servers were not enumerated: servers were not started or contacted.",
    "Runtime environment variables, OS sandboxing, and network egress controls cannot be verified from files.",
  ];
  if (files.truncated) notVerified.push("File limit reached; some files were not examined.");
  for (const rel of files.skippedLarge) notVerified.push(`Skipped large file: ${rel}`);

  const agents: Array<AgentSignal> = [];
  for (const marker of AGENT_MARKERS) {
    const hits = files.paths.filter((p) => marker.match.test(p));
    if (hits.length > 0) {
      agents.push({
        agent: marker.agent,
        evidence: hits
          .slice(0, 5)
          .map((file) => ({ file, detail: "agent configuration file present" })),
      });
    }
  }

  const mcpServers: Array<McpServer> = [];
  const permissions: Array<PermissionSetting> = [];

  for (const spec of MCP_JSON_FILES) {
    if (!files.has(spec.file)) continue;
    const doc = parseJson(files, spec.file, notVerified);
    const servers = doc?.[spec.key];
    if (!isRecord(servers)) continue;
    for (const [name, raw] of Object.entries(servers)) {
      if (isRecord(raw)) mcpServers.push(toMcpServer(files, spec.file, spec.client, name, raw));
    }
  }

  for (const file of [".claude/settings.json", ".claude/settings.local.json"]) {
    if (!files.has(file)) continue;
    const doc = parseJson(files, file, notVerified);
    const perms = doc && isRecord(doc.permissions) ? doc.permissions : undefined;
    if (!perms) continue;
    if (typeof perms.defaultMode === "string") {
      permissions.push({
        client: "Claude Code",
        file,
        key: "permissions.defaultMode",
        value: perms.defaultMode,
        ...lineProp(files.lineOf(file, '"defaultMode"')),
      });
    }
    for (const entry of strings(perms.allow)) {
      permissions.push({
        client: "Claude Code",
        file,
        key: "permissions.allow",
        value: entry,
        ...lineProp(files.lineOf(file, JSON.stringify(entry))),
      });
    }
  }

  if (files.has(".codex/config.toml")) readCodexToml(files, mcpServers, permissions);

  const workflowDocs = new Map<string, WorkflowDoc>();
  const workflows: Array<WorkflowEntry> = [];
  for (const file of files.paths.filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p))) {
    const doc = parseYaml(files, file, notVerified);
    if (!doc) continue;
    workflowDocs.set(file, doc);
    workflows.push(describeWorkflow(files, file, doc));
  }
  const ciEvidence: Array<Evidence> = workflows.flatMap((wf) =>
    wf.agentSteps.map((s) => ({
      file: wf.file,
      ...lineProp(s.line),
      detail: `${s.agent} in job ${s.job}`,
    })),
  );
  if (ciEvidence.length > 0)
    agents.push({ agent: "CI agent (GitHub Actions)", evidence: ciEvidence });

  return {
    inventory: {
      agents,
      instructionFiles: files.paths.filter((p) => INSTRUCTION_FILE.test(p)),
      skills: discoverSkills(files),
      mcpServers,
      permissions,
      workflows,
      credentialRefs: collectCredentialRefs(files, [
        ...MCP_JSON_FILES.map((s) => s.file),
        ".codex/config.toml",
        ...workflows.map((w) => w.file),
      ]),
      filesExamined: files.paths.length,
      notVerified,
    },
    workflowDocs,
  };
}

function parseJson(files: ProjectFiles, file: string, notVerified: Array<string>) {
  try {
    const doc: unknown = JSON.parse(files.read(file) ?? "");
    return isRecord(doc) ? doc : undefined;
  } catch {
    notVerified.push(`${file} is not valid JSON and was not interpreted.`);
    return undefined;
  }
}

function parseYaml(files: ProjectFiles, file: string, notVerified: Array<string>) {
  try {
    const doc: unknown = Yaml.parse(files.read(file) ?? "");
    return isRecord(doc) ? doc : undefined;
  } catch {
    notVerified.push(`${file} is not valid YAML and was not interpreted.`);
    return undefined;
  }
}

function discoverSkills(files: ProjectFiles): Array<SkillEntry> {
  return files.paths
    .filter((p) => p === "SKILL.md" || p.endsWith("/SKILL.md"))
    .map((skillFile) => {
      const dir = NodePath.posix.dirname(skillFile);
      const text = files.read(skillFile) ?? "";
      const name = /^name:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? NodePath.posix.basename(dir);
      const allowedTools = /^allowed-tools:\s*(.+)$/m.exec(text)?.[1]?.trim();
      return {
        name,
        dir,
        files: files.paths.filter((p) => p.startsWith(`${dir}/`)),
        ...(allowedTools ? { allowedTools } : {}),
      };
    });
}

function toMcpServer(
  files: ProjectFiles,
  file: string,
  client: string,
  name: string,
  raw: Record<string, unknown>,
): McpServer {
  // OpenCode uses `command: [cmd, ...args]` and `environment`.
  const commandList = strings(raw.command);
  const command = typeof raw.command === "string" ? raw.command : commandList[0];
  const args = commandList.length > 0 ? commandList.slice(1) : strings(raw.args);
  const url = [raw.url, raw.httpUrl, raw.serverUrl].find((v): v is string => typeof v === "string");
  return {
    name,
    client,
    file,
    ...lineProp(files.lineOf(file, `"${name}"`)),
    transport: url ? "http" : command ? "stdio" : "unknown",
    ...(command ? { command } : {}),
    args,
    ...(url ? { url } : {}),
    envKeys: [...keysOf(raw.env), ...keysOf(raw.environment)],
    headerKeys: keysOf(raw.headers),
  };
}

// Line-oriented reader for the few Codex keys we check: flat `key = value`
// pairs and table headers do not need a full TOML parser.
function readCodexToml(
  files: ProjectFiles,
  servers: Array<McpServer>,
  permissions: Array<PermissionSetting>,
) {
  const file = ".codex/config.toml";
  let table = "";
  let current:
    | { name: string; line: number; fields: Record<string, string>; env: Array<string> }
    | undefined;
  const unquote = (v: string | undefined) => v?.replace(/^"|"$/g, "");
  const flush = () => {
    if (!current) return;
    const command = unquote(current.fields.command);
    const url = unquote(current.fields.url);
    servers.push({
      name: current.name,
      client: "Codex",
      file,
      line: current.line,
      transport: url ? "http" : command ? "stdio" : "unknown",
      ...(command ? { command } : {}),
      args: [...(current.fields.args ?? "").matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!),
      ...(url ? { url } : {}),
      envKeys: current.env,
      headerKeys: [],
    });
    current = undefined;
  };
  (files.read(file) ?? "").split("\n").forEach((text, i) => {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(text);
    if (header) {
      table = header[1]!.trim();
      const server = /^mcp_servers\.([^.]+)$/.exec(table);
      if (server) {
        flush();
        current = { name: server[1]!.replace(/"/g, ""), line: i + 1, fields: {}, env: [] };
      } else if (!table.startsWith("mcp_servers.")) {
        flush();
      }
      return;
    }
    const kv = /^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$/.exec(text);
    if (!kv) return;
    const key = kv[1]!;
    const value = kv[2]!;
    if (table === "" && (key === "approval_policy" || key === "sandbox_mode")) {
      permissions.push({ client: "Codex", file, line: i + 1, key, value: unquote(value)! });
    } else if (current && table.endsWith(".env")) {
      current.env.push(key);
    } else if (current) {
      current.fields[key] = value;
    }
  });
  flush();
}

function triggersOf(doc: WorkflowDoc): Array<string> {
  const on = doc.on;
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return strings(on);
  return keysOf(on);
}

export function stepsOf(job: unknown): Array<Record<string, unknown>> {
  return isRecord(job) && Array.isArray(job.steps) ? job.steps.filter(isRecord) : [];
}

export function agentOfStep(step: Record<string, unknown>): string | undefined {
  if (typeof step.uses === "string" && AGENT_ACTION.test(step.uses)) return step.uses;
  if (typeof step.run === "string") {
    const cli = AGENT_CLI.exec(step.run);
    if (cli) return `${cli[2]} CLI`;
  }
  return undefined;
}

export function stepAnchor(step: Record<string, unknown>): string {
  return typeof step.uses === "string" ? step.uses : String(step.run).split("\n")[0]!;
}

function describeWorkflow(files: ProjectFiles, file: string, doc: WorkflowDoc): WorkflowEntry {
  const jobs = isRecord(doc.jobs) ? doc.jobs : {};
  const agentSteps: Array<WorkflowEntry["agentSteps"][number]> = [];
  const reusableCalls: Array<WorkflowEntry["reusableCalls"][number]> = [];
  for (const [jobName, job] of Object.entries(jobs)) {
    if (isRecord(job) && typeof job.uses === "string") {
      reusableCalls.push({ job: jobName, uses: job.uses });
    }
    const jobLine = files.lineOf(file, new RegExp(`^\\s+${jobName}:`));
    for (const step of stepsOf(job)) {
      const agent = agentOfStep(step);
      if (!agent) continue;
      agentSteps.push({
        job: jobName,
        agent,
        ...lineProp(files.lineOf(file, stepAnchor(step), jobLine)),
      });
    }
  }
  return { file, triggers: triggersOf(doc), agentSteps, reusableCalls };
}

function collectCredentialRefs(
  files: ProjectFiles,
  candidates: ReadonlyArray<string>,
): Array<CredentialRef> {
  const refs: Array<CredentialRef> = [];
  const patterns = [
    /\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g,
    /\$\{(?:env:)?([A-Z][A-Z0-9_]*)\}/g,
  ];
  for (const file of candidates) {
    if (!files.has(file)) continue;
    (files.read(file) ?? "").split("\n").forEach((text, i) => {
      for (const pattern of patterns) {
        for (const m of text.matchAll(pattern)) refs.push({ name: m[1]!, file, line: i + 1 });
      }
    });
  }
  return refs;
}
