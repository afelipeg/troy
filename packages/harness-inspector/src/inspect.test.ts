// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeChildProcess from "node:child_process";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { describe, expect, it } from "vite-plus/test";
import { inspect } from "./inspect.ts";
import { writeReport } from "./report.ts";

const outDir = () => NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-out-"));

const FIXTURE = NodePath.join(import.meta.dirname, "..", "fixtures", "demo-harness");

const copyFixture = () => {
  const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-inspector-"));
  NodeFS.cpSync(FIXTURE, dir, {
    recursive: true,
    filter: (src) => !src.includes(".harness-inspector"),
  });
  return dir;
};

const statusOf = (report: ReturnType<typeof inspect>, file: string, ruleId: string) =>
  report.findings
    .filter((f) => f.ruleId === ruleId && f.evidence.some((e) => e.file === file))
    .map((f) => f.status);

describe("inspect demo harness", () => {
  const report = inspect(FIXTURE);

  it("discovers the harness components", () => {
    expect(report.inventory.agents.map((a) => a.agent)).toEqual(
      expect.arrayContaining(["Claude Code", "Codex", "CI agent (GitHub Actions)"]),
    );
    expect(report.inventory.mcpServers.map((s) => s.name).sort()).toEqual([
      "analytics",
      "docs",
      "filesystem",
      "vendor-search",
    ]);
    expect(report.inventory.skills.map((s) => s.name)).toEqual(["release-notes"]);
  });

  it("confirms the risky CI path with line evidence", () => {
    const triage = report.findings.find((f) => f.title.includes('"triage"'))!;
    expect(triage.status).toBe("confirmed");
    expect(triage.evidence).toContainEqual(
      expect.objectContaining({ file: ".github/workflows/agent-triage.yml", line: 18 }),
    );
    expect(triage.fix.patch).toContain("author_association");
  });

  it("marks the gated, similar workflow mitigated rather than safe", () => {
    expect(statusOf(report, ".github/workflows/agent-maintainer.yml", "HI-CI-001")).toEqual([
      "mitigated",
    ]);
  });

  it("marks the incomplete cases unverifiable", () => {
    expect(statusOf(report, ".github/workflows/agent-review.yml", "HI-CI-001")).toEqual([
      "unverifiable",
    ]);
    expect(report.findings.find((f) => f.title.includes("vendor-search"))?.status).toBe(
      "unverifiable",
    );
  });

  it("flags only the unscoped filesystem server and ignores benign settings", () => {
    const fsFindings = report.findings.filter((f) => f.title.startsWith("Filesystem MCP"));
    expect(fsFindings.map((f) => [f.title, f.status])).toEqual([
      [
        'Filesystem MCP server "filesystem" is configured to reach the whole home or root directory',
        "probable",
      ],
    ]);
    expect(report.findings.filter((f) => f.ruleId === "HI-PERM-001")).toEqual([]);
  });

  it("never copies credential values into reports", () => {
    const out = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-report-"));
    const written = writeReport(report, out);
    const json = NodeFS.readFileSync(written.json, "utf8");
    const markdown = NodeFS.readFileSync(written.markdown, "utf8");
    expect(JSON.parse(json).schemaVersion).toBe(1);
    expect(markdown).toContain("## Findings");
    expect(json + markdown).not.toContain("fx-demo-0001");
  });

  it("produces a patch that applies to the project without being applied", () => {
    const dir = copyFixture();
    const before = NodeFS.readFileSync(NodePath.join(dir, ".mcp.json"), "utf8");
    const written = writeReport(inspect(dir), outDir());
    expect(NodeFS.readFileSync(NodePath.join(dir, ".mcp.json"), "utf8")).toBe(before);
    NodeChildProcess.execFileSync("git", ["init", "-q"], { cwd: dir });
    NodeChildProcess.execFileSync("git", ["apply", "--check", written.patch!], { cwd: dir });
  });
});

it("confirms key-shaped credentials and withholds them", () => {
  const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-cred-"));
  // Built at run time so no key-shaped literal lives in the repository.
  const value = ["sk", "ant", "a".repeat(32)].join("-");
  NodeFS.writeFileSync(NodePath.join(dir, "config.ts"), `export const key = "${value}";\n`);
  const report = inspect(dir);
  const finding = report.findings.find((f) => f.ruleId === "HI-SECRET-001")!;
  expect(finding.status).toBe("confirmed");
  expect(JSON.stringify(report)).not.toContain(value);
});

it("never starts the MCP servers it reads", () => {
  const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-exec-"));
  const marker = NodePath.join(dir, "started");
  NodeFS.writeFileSync(
    NodePath.join(dir, ".mcp.json"),
    JSON.stringify({ mcpServers: { probe: { command: "sh", args: ["-c", `touch ${marker}`] } } }),
  );
  writeReport(inspect(dir), outDir());
  expect(NodeFS.existsSync(marker)).toBe(false);
});

it("escapes project content in the HTML summary", () => {
  const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-html-"));
  NodeFS.writeFileSync(
    NodePath.join(dir, ".mcp.json"),
    JSON.stringify({ mcpServers: { "<script>alert(1)</script>": { url: "https://x.invalid" } } }),
  );
  const html = NodeFS.readFileSync(writeReport(inspect(dir), outDir()).html, "utf8");
  expect(html).not.toContain("<script");
  expect(html).toContain("&#60;script&#62;");
});

it("reports whether the session runs inside the inspected project", () => {
  expect(inspect(FIXTURE, { sessionCwd: FIXTURE }).sessionMode).toMatch(/^session-inside-target/);
  const outside = inspect(FIXTURE, { sessionCwd: NodeOS.tmpdir() }).sessionMode;
  expect(outside).toMatch(/^session-outside-target/);
  expect(outside).toContain("This is not a sandbox");
});

describe("run identity", () => {
  it("keeps finding ids when lines shift between runs", () => {
    const dir = copyFixture();
    const before = inspect(dir)
      .findings.map((f) => f.id)
      .sort();
    const workflow = NodePath.join(dir, ".github/workflows/agent-triage.yml");
    NodeFS.writeFileSync(workflow, `# moved\n\n${NodeFS.readFileSync(workflow, "utf8")}`);
    expect(
      inspect(dir)
        .findings.map((f) => f.id)
        .sort(),
    ).toEqual(before);
  });

  it("stamps one run id on the JSON, Markdown, HTML and patch it writes", () => {
    const out = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-run-"));
    const report = inspect(FIXTURE);
    const written = writeReport(report, out);
    expect(JSON.parse(NodeFS.readFileSync(written.json, "utf8")).runId).toBe(report.runId);
    for (const file of [written.markdown, written.html, written.patch!]) {
      expect(NodeFS.readFileSync(file, "utf8")).toContain(report.runId);
    }
    expect(inspect(FIXTURE).runId).not.toBe(report.runId);
  });

  it("compares with the previous run after the proposed patch is applied", () => {
    const dir = copyFixture();
    const first = inspect(dir);
    const written = writeReport(first, outDir());
    NodeChildProcess.execFileSync("git", ["init", "-q"], { cwd: dir });
    NodeChildProcess.execFileSync("git", ["apply", written.patch!], { cwd: dir });
    const second = inspect(dir, { previous: first });
    const triage = first.findings.find((f) => f.subject.endsWith("#triage"))!;
    const rootFs = first.findings.find((f) => f.subject.endsWith(":filesystem:/"))!;
    expect(second.comparison?.previousRunId).toBe(first.runId);
    expect(second.comparison?.persisting).toContainEqual({
      id: triage.id,
      from: "confirmed",
      to: "mitigated",
    });
    expect(second.comparison?.noLongerDetectedIds).toEqual([rootFs.id]);
    expect(second.comparison?.newIds).toEqual([]);
  });
});

it("describes the approval configuration without claiming the effective mode", () => {
  const plain = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-session-"));
  const none = inspect(FIXTURE, { sessionCwd: plain }).approvalConfig;
  expect(none).toMatch(/^none detected/);
  expect(none).toContain("Effective permission mode: not verified");
  expect(none).toContain("not a control");
  NodeFS.mkdirSync(NodePath.join(plain, ".claude"));
  NodeFS.writeFileSync(
    NodePath.join(plain, ".claude", "settings.json"),
    JSON.stringify({ permissions: { disableBypassPermissionsMode: "disable" } }),
  );
  const guarded = inspect(FIXTURE, { sessionCwd: plain }).approvalConfig;
  expect(guarded).toMatch(/^detected: /);
  expect(guarded).toContain("Effective permission mode: not verified");
  expect(guarded).toContain("not equivalent to Supervised");
});

it("refuses to write reports inside the inspected project", () => {
  const dir = copyFixture();
  expect(() => writeReport(inspect(dir), NodePath.join(dir, ".harness-inspector"))).toThrow(
    /inside the inspected project/,
  );
  expect(NodeFS.existsSync(NodePath.join(dir, ".harness-inspector"))).toBe(false);
});

it("ends quietly when the folder picker is cancelled", () => {
  const bin = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-shim-"));
  NodeFS.writeFileSync(NodePath.join(bin, "osascript"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
  const cwd = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "harness-cancel-"));
  const script = NodePath.join(import.meta.dirname, "..", "scripts", "pick-and-inspect.ts");
  const result = NodeChildProcess.spawnSync(process.execPath, [script], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}${NodePath.delimiter}${process.env.PATH ?? ""}` },
  });
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("Inspección cancelada");
  expect(result.stdout + result.stderr).not.toContain("usage");
  expect(NodeFS.readdirSync(cwd)).toEqual([]);
});
