// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeCrypto from "node:crypto";
import * as NodePath from "node:path";
import {
  agentOfStep,
  isRecord,
  lineProp,
  stepAnchor,
  stepsOf,
  type Discovery,
} from "./discover.ts";
import { linePatch } from "./patch.ts";
import type { ProjectFiles } from "./projectFiles.ts";
import type { Evidence, Finding, McpServer, VerificationStatus } from "./types.ts";

type Draft = Omit<Finding, "id">;

export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly run: (files: ProjectFiles, discovery: Discovery) => ReadonlyArray<Draft>;
}

// Events whose payload can be authored by someone without write access.
const UNTRUSTED_TRIGGERS: Record<string, string> = {
  issue_comment: "github.event.comment.author_association",
  pull_request_review_comment: "github.event.comment.author_association",
  pull_request_review: "github.event.review.author_association",
  issues: "github.event.issue.author_association",
  pull_request_target: "github.event.pull_request.author_association",
  discussion: "github.event.discussion.author_association",
  discussion_comment: "github.event.comment.author_association",
};
const ATTACKER_EXPRESSION =
  /\$\{\{\s*github\.(event\.(issue\.(title|body)|comment\.body|pull_request\.(title|body|head\.ref)|review\.body|discussion\.(title|body)|head_commit\.message)|head_ref)\s*\}\}/;
const DANGEROUS_AGENT_FLAG =
  /--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|danger-full-access|Bash\(\*\)/;

type TokenAccess = "write" | "read" | "unknown";

function tokenAccess(permissions: unknown): { access: TokenAccess; scopes: Array<string> } {
  if (permissions === undefined) return { access: "unknown", scopes: [] };
  if (permissions === "write-all") return { access: "write", scopes: ["write-all"] };
  if (!isRecord(permissions)) return { access: "read", scopes: [] };
  const scopes = Object.entries(permissions)
    .filter(([, v]) => v === "write")
    .map(([k]) => `${k}: write`);
  return { access: scopes.length > 0 ? "write" : "read", scopes };
}

// A gate counts only when it names trusted associations and none of the open ones.
function isTrustedGate(condition: unknown): boolean {
  if (typeof condition !== "string") return false;
  return (
    /author_association/.test(condition) &&
    /OWNER|MEMBER|COLLABORATOR/.test(condition) &&
    !/NONE|FIRST_TIME|CONTRIBUTOR"|'CONTRIBUTOR/.test(condition)
  );
}

const ciRule: Rule = {
  id: "HI-CI-001",
  title: "Untrusted event content can reach a CI agent with sensitive permissions",
  run(files, { workflowDocs }) {
    const drafts: Array<Draft> = [];
    for (const [file, doc] of workflowDocs) {
      const on = doc.on;
      const triggers =
        typeof on === "string"
          ? [on]
          : Array.isArray(on)
            ? on.map(String)
            : Object.keys(isRecord(on) ? on : {});
      const untrusted = triggers.filter((t) => t in UNTRUSTED_TRIGGERS);
      if (untrusted.length === 0) continue;
      const jobs = isRecord(doc.jobs) ? doc.jobs : {};
      for (const [jobName, job] of Object.entries(jobs)) {
        if (!isRecord(job)) continue;
        const jobLine = files.lineOf(file, new RegExp(`^\\s+${jobName}:`));
        const triggerEvidence: Evidence = {
          file,
          ...lineProp(files.lineOf(file, new RegExp(`\\b${untrusted[0]}\\b`))),
          detail: `triggered by ${untrusted.join(", ")} (payload authored outside the repository's write team)`,
        };

        if (typeof job.uses === "string") {
          drafts.push({
            ruleId: this.id,
            title: `Reusable workflow called from untrusted trigger cannot be inspected (${jobName})`,
            subject: `ci:${file}#${jobName}`,
            surface: "ci",
            category: "untrusted-input-to-agent",
            owasp: ["ASI01", "ASI03"],
            status: "unverifiable",
            evidence: [
              triggerEvidence,
              {
                file,
                ...lineProp(files.lineOf(file, job.uses)),
                detail: `job delegates to ${job.uses}`,
              },
            ],
            preconditions: [
              "The called workflow runs an agent on event content.",
              "The called workflow receives write permissions or secrets.",
            ],
            impact: "Unknown: the steps that run are defined outside the inspected files.",
            fix: {
              summary:
                "Inspect the called workflow, pin it to a commit SHA, and declare minimal `permissions:` on this job.",
            },
            verification: "Re-run the inspector with the called workflow available locally.",
            limitations: ["Remote workflow content was not fetched."],
          });
          continue;
        }

        const agentSteps = stepsOf(job).filter((s) => agentOfStep(s) !== undefined);
        if (agentSteps.length === 0) continue;
        const { access, scopes } = tokenAccess(job.permissions ?? doc.permissions);
        const gated = isTrustedGate(job.if) || agentSteps.every((s) => isTrustedGate(s.if));

        const evidence: Array<Evidence> = [triggerEvidence];
        let directInput = false;
        let passesSecrets = false;
        for (const step of agentSteps) {
          const stepLine = files.lineOf(file, stepAnchor(step), jobLine);
          evidence.push({
            file,
            ...lineProp(stepLine),
            detail: `agent step: ${agentOfStep(step)}`,
          });
          const stepText = JSON.stringify({ with: step.with, env: step.env, run: step.run });
          const expr = ATTACKER_EXPRESSION.exec(stepText);
          if (expr) {
            directInput = true;
            evidence.push({
              file,
              ...lineProp(files.lineOf(file, expr[0], stepLine)),
              detail: `attacker-controlled expression ${expr[0]} interpolated into the agent step`,
            });
          }
          if (/secrets\./.test(stepText)) passesSecrets = true;
          const flag = DANGEROUS_AGENT_FLAG.exec(stepText);
          if (flag) {
            evidence.push({
              file,
              ...lineProp(files.lineOf(file, flag[0], stepLine)),
              detail: `agent runs with ${flag[0]}`,
            });
          }
        }
        const permLine = files.lineOf(file, /^\s*permissions:/);
        evidence.push(
          access === "unknown"
            ? {
                file,
                detail:
                  "no `permissions:` block; effective GITHUB_TOKEN scope depends on repository settings",
              }
            : {
                file,
                ...lineProp(permLine),
                detail: `GITHUB_TOKEN access: ${access}${scopes.length ? ` (${scopes.join(", ")})` : ""}`,
              },
        );
        if (gated) {
          evidence.push({
            file,
            ...lineProp(files.lineOf(file, "author_association", jobLine)),
            detail: "job is gated to trusted author associations",
          });
        }

        let status: VerificationStatus;
        if (gated) status = "mitigated";
        else if (access === "write" && directInput) status = "confirmed";
        else if (access === "write" || (directInput && access === "unknown")) status = "probable";
        else if (access === "unknown") status = "unverifiable";
        else status = passesSecrets ? "probable" : "dismissed";

        const gateField = UNTRUSTED_TRIGGERS[untrusted[0]!]!;
        const jobIndent = /^\s*/.exec(files.lineText(file, jobLine ?? 1))![0];
        const patch =
          !gated && jobLine !== undefined && job.if === undefined
            ? linePatch(files, file, jobLine, {
                insertAfter: [
                  `${jobIndent}  if: contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), ${gateField})`,
                ],
              })
            : undefined;

        drafts.push({
          ruleId: this.id,
          title: `${untrusted.join("/")} content reaches agent job "${jobName}"`,
          subject: `ci:${file}#${jobName}`,
          surface: "ci",
          category: "untrusted-input-to-agent",
          owasp: ["ASI01", "ASI03"],
          status,
          evidence,
          preconditions: [
            "An outside user can open an issue, comment, or pull request on the repository.",
            directInput
              ? "Event text is interpolated directly into the agent prompt or command (observed)."
              : "The agent action reads event text on its own (inferred from the action's purpose; not observed).",
            access === "write"
              ? "The job token has write scopes (observed)."
              : access === "unknown"
                ? "The repository default token permission is write (not verifiable from files)."
                : "Secrets passed to the agent are worth exfiltrating.",
          ],
          impact: gated
            ? "The observed gate keeps users outside OWNER/MEMBER/COLLABORATOR from starting this job, which removes the path this rule checks. Residual risk remains: a trusted account that is compromised or quotes untrusted text still reaches the agent with this job's permissions and secrets."
            : "Prompt injection in the event text could steer the agent into pushing code, editing issues or PRs, or leaking secrets available to the job.",
          fix: {
            summary: gated
              ? "Keep the author_association gate. It is not a full safety assessment: also pass event text through an environment variable treated as data and reduce `permissions:` to what the agent needs."
              : "Gate the job to trusted authors, pass event text through an environment variable treated as data instead of interpolating it, and reduce `permissions:` to the scopes the agent needs.",
            ...(patch && !gated && status !== "dismissed" ? { patch } : {}),
          },
          verification:
            "Re-run the inspector: the finding should become mitigated, not dismissed. In a sandbox fork, a comment from a non-collaborator must not start the job.",
          limitations: [
            "Static reading only: action internals and repository settings were not inspected.",
            "Expressions built indirectly (env intermediaries, scripts) may not be detected.",
            ...(gated
              ? [
                  "Mitigated only for this rule's path; the gate was read from YAML, not tested against GitHub.",
                ]
              : []),
          ],
        });
      }
    }
    return drafts;
  },
};

const SHELL_LAUNCHERS = new Set(["npx", "bunx", "uvx", "pnpx"]);
const EXEC_SERVER = /(^|[-_/@])(shell|terminal|exec|desktop-commander|commands?)([-_/@.]|$)/i;

function packageArg(server: McpServer): string | undefined {
  if (!server.command) return undefined;
  const base = NodePath.basename(server.command);
  const args = base === "pnpm" || base === "bun" ? server.args.slice(1) : server.args;
  if (!SHELL_LAUNCHERS.has(base) && !(base === "pnpm" && server.args[0] === "dlx"))
    return undefined;
  return args.find((a) => !a.startsWith("-"));
}

const isPinned = (pkg: string) =>
  /^@?[^@]+@\d/.test(pkg) || pkg.startsWith(".") || pkg.startsWith("/");

function broadPathKind(arg: string, root: string): "home-or-root" | "outside" | undefined {
  if (
    ["/", "~", "~/", "$HOME", "${HOME}"].includes(arg) ||
    /^\/(Users|home)\/[^/]+\/?$/.test(arg)
  ) {
    return "home-or-root";
  }
  if (NodePath.isAbsolute(arg) && NodePath.relative(root, arg).startsWith("..")) return "outside";
  return undefined;
}

const mcpRule: Rule = {
  id: "HI-MCP-001",
  title: "MCP server with broad or unverifiable access",
  run(files, { inventory }) {
    const drafts: Array<Draft> = [];
    for (const server of inventory.mcpServers) {
      const where: Evidence = {
        file: server.file,
        ...lineProp(server.line),
        detail: `MCP server "${server.name}" declared for ${server.client}`,
      };
      const ident = [server.name, server.command ?? "", ...server.args].join(" ");

      if (/server-filesystem|(^|\s)filesystem(\s|$)/.test(ident)) {
        const pkg = packageArg(server);
        const paths = server.args.filter((a) => !a.startsWith("-") && a !== pkg && a !== "dlx");
        for (const arg of paths) {
          const kind = broadPathKind(arg, files.root);
          if (!kind) continue;
          const argLine = files.lineOf(server.file, `"${arg}"`, server.line);
          const patch =
            argLine === undefined
              ? undefined
              : linePatch(files, server.file, argLine, {
                  replaceWith: files.lineText(server.file, argLine).replace(`"${arg}"`, '"."'),
                });
          drafts.push({
            ruleId: this.id,
            subject: `mcp:${server.file}#${server.name}:filesystem:${arg}`,
            title: `Filesystem MCP server "${server.name}" is configured to reach ${kind === "home-or-root" ? "the whole home or root directory" : "paths outside the project"}`,
            surface: "mcp",
            category: "excessive-tool-scope",
            owasp: ["ASI02", "ASI03"],
            status: "probable",
            evidence: [
              where,
              {
                file: server.file,
                ...lineProp(argLine),
                detail: `allowed directory argument: ${arg}`,
              },
            ],
            preconditions: [
              `${server.client} loads this project's MCP configuration and the user approves the server.`,
              "The client does not narrow the server through MCP roots. Some clients send roots that replace the command-line directories in recent server versions; the package is not always pinned, so this varies.",
              "The agent receives instructions that make it read or write outside the task's scope.",
            ],
            impact:
              "Read and write access to credentials, SSH keys, and other projects under the allowed directory.",
            fix: {
              summary:
                'Limit the server\'s allowed directories to the project (or a subdirectory it needs). A relative path such as "." resolves against the directory the client launches the server from, so it is not a barrier by itself: confirm the effective scope.',
              ...(patch ? { patch } : {}),
            },
            verification:
              "Start the server the way the client does and confirm list_allowed_directories returns only the project path, and that paths outside it and symlinks pointing outside it are denied.",
            limitations: [
              "Effective scope depends on the client's launch directory, MCP roots support and the server version; none of these are visible in the configuration.",
            ],
          });
        }
      }

      if (EXEC_SERVER.test(ident)) {
        drafts.push({
          ruleId: this.id,
          title: `MCP server "${server.name}" appears to expose command execution`,
          subject: `mcp:${server.file}#${server.name}:exec`,
          surface: "mcp",
          category: "excessive-tool-scope",
          owasp: ["ASI02", "ASI05"],
          status: "unverifiable",
          evidence: [
            where,
            {
              file: server.file,
              ...lineProp(server.line),
              detail:
                `identified by name/arguments: ${server.command ?? ""} ${server.args.join(" ")}`.trim(),
            },
          ],
          preconditions: [
            "The server really exposes a shell or exec tool (inferred from its name only).",
          ],
          impact: "If confirmed, any instruction that reaches the agent can become a host command.",
          fix: {
            summary: "Confirm the server's tools; prefer an allowlist of commands or remove it.",
          },
          verification:
            "List the server's tools in a sandbox and check for exec-style tools and their limits.",
          limitations: ["Classification is based on naming; tools were not enumerated."],
        });
      }

      if (server.transport === "http") {
        drafts.push({
          ruleId: this.id,
          title: `Remote MCP server "${server.name}" has tools and data handling that cannot be verified locally`,
          subject: `mcp:${server.file}#${server.name}:remote`,
          surface: "mcp",
          category: "unverifiable-remote-tool",
          owasp: ["ASI02", "ASI04"],
          status: "unverifiable",
          evidence: [
            where,
            {
              file: server.file,
              ...lineProp(server.line),
              detail: `endpoint host ${safeHost(server.url)}; auth header keys: ${server.headerKeys.length ? server.headerKeys.join(", ") : "none declared"}`,
            },
          ],
          preconditions: [
            "Unknown: tool list, permissions and data retention live on the remote service.",
          ],
          impact:
            "Data the agent sends to this endpoint leaves the machine; tool behavior is controlled remotely.",
          fix: {
            summary:
              "Document the server's tools and scopes, or restrict which tools the client may call.",
          },
          verification:
            "Enumerate the server's tools with an authorized client and record them next to the config.",
          limitations: ["The endpoint was not contacted."],
        });
      }
    }
    return drafts;
  },
};

const safeHost = (url: string | undefined) => {
  try {
    return url ? new URL(url).host : "unknown";
  } catch {
    return "unparseable URL";
  }
};

const supplyChainRule: Rule = {
  id: "HI-MCP-002",
  title: "MCP server launched from an unpinned package",
  run(_files, { inventory }) {
    return inventory.mcpServers.flatMap((server) => {
      const pkg = packageArg(server);
      if (!pkg || isPinned(pkg)) return [];
      return [
        {
          ruleId: this.id,
          title: `MCP server "${server.name}" runs the latest published version of ${pkg}`,
          subject: `mcp:${server.file}#${server.name}:package`,
          surface: "mcp",
          category: "supply-chain",
          owasp: ["ASI04"],
          status: "probable",
          evidence: [
            {
              file: server.file,
              ...lineProp(server.line),
              detail: `${server.command} ${server.args.join(" ")} (no version pin)`,
            },
          ],
          preconditions: ["A future or compromised release of the package is published."],
          impact: "New code runs with the agent's tool permissions on next start, without review.",
          fix: { summary: `Pin the package to a reviewed version, e.g. ${pkg}@<version>.` },
          verification: "Re-run the inspector; the finding disappears once a version is pinned.",
          limitations: ["Package contents and provenance were not checked."],
        } satisfies Draft,
      ];
    });
  },
};

const permissionRule: Rule = {
  id: "HI-PERM-001",
  title: "Agent approval or sandbox disabled in configuration",
  run(files, { inventory }) {
    const drafts: Array<Draft> = [];
    const base = {
      ruleId: this.id,
      surface: "permissions" as const,
      category: "approval-disabled",
      owasp: ["ASI02", "ASI05"],
      verification:
        "Re-run the inspector and start the agent: a shell command must prompt for approval.",
    };
    for (const p of inventory.permissions) {
      const evidence = [{ file: p.file, ...lineProp(p.line), detail: `${p.key} = ${p.value}` }];
      if (p.key === "permissions.defaultMode" && p.value === "bypassPermissions") {
        const patch =
          p.line === undefined
            ? undefined
            : linePatch(files, p.file, p.line, {
                replaceWith: files.lineText(p.file, p.line).replace("bypassPermissions", "default"),
              });
        drafts.push({
          ...base,
          title: `${p.client} skips every permission prompt in ${p.file}`,
          subject: `perm:${p.file}#${p.key}`,
          status: "confirmed",
          evidence,
          preconditions: ["The agent is started in this project with these settings."],
          impact: "Every tool call, including shell and file writes, runs without human approval.",
          fix: {
            summary: "Use the default mode and allow specific commands instead.",
            ...(patch ? { patch } : {}),
          },
          limitations: [
            "User-level or managed settings can override project settings and were not read.",
          ],
        });
      } else if (p.key === "permissions.allow" && /^Bash(\((\*|:\*)?\))?$/.test(p.value)) {
        drafts.push({
          ...base,
          title: `${p.client} auto-approves every shell command (${p.value})`,
          subject: `perm:${p.file}#allow:${p.value}`,
          status: "confirmed",
          evidence,
          preconditions: ["The agent is started in this project with these settings."],
          impact:
            "Any instruction reaching the agent can run arbitrary host commands without a prompt.",
          fix: {
            summary:
              "Replace the wildcard with the specific commands the workflow needs, e.g. Bash(npm test).",
          },
          limitations: [
            "User-level or managed settings can override project settings and were not read.",
          ],
        });
      } else if (
        (p.key === "approval_policy" && p.value === "never") ||
        (p.key === "sandbox_mode" && p.value === "danger-full-access")
      ) {
        const both =
          inventory.permissions.some((q) => q.key === "approval_policy" && q.value === "never") &&
          inventory.permissions.some(
            (q) => q.key === "sandbox_mode" && q.value === "danger-full-access",
          );
        drafts.push({
          ...base,
          title: `Codex ${p.key} = ${p.value}`,
          subject: `perm:${p.file}#${p.key}`,
          status: both ? "confirmed" : "probable",
          evidence,
          preconditions: [
            both
              ? "Approvals are off and the sandbox is disabled (both observed)."
              : "The other control (approval or sandbox) does not compensate (only one was observed).",
          ],
          impact: "Commands chosen by the model run on the host without review.",
          fix: {
            summary: 'Use approval_policy = "on-request" with sandbox_mode = "workspace-write".',
          },
          limitations: ["CLI flags and profiles can override config.toml and were not observed."],
        });
      }
    }
    for (const file of files.paths.filter((f) =>
      /\.(sh|bash|zsh|ya?ml|json|toml|mk)$|(^|\/)Makefile$/.test(f),
    )) {
      const text = files.read(file);
      if (!text) continue;
      const flag =
        /--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b/.exec(
          text,
        );
      if (!flag || file.startsWith(".github/workflows/")) continue;
      drafts.push({
        ...base,
        title: `${file} launches an agent with ${flag[0]}`,
        subject: `perm:${file}#flag:${flag[0]}`,
        status: "confirmed",
        evidence: [
          { file, ...lineProp(files.lineOf(file, flag[0])), detail: `flag ${flag[0]} present` },
        ],
        preconditions: ["The script or config is used to start the agent."],
        impact: "The launched agent runs every tool call without approval.",
        fix: { summary: "Drop the flag, or run that launch only inside a disposable sandbox." },
        limitations: ["Whether and where this launcher is used was not verified."],
      });
    }
    return drafts;
  },
};

const CREDENTIAL_PATTERNS: ReadonlyArray<{ kind: string; pattern: RegExp }> = [
  { kind: "Anthropic API key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { kind: "OpenAI API key", pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  {
    kind: "GitHub token",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/,
  },
  { kind: "AWS access key id", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { kind: "Google API key", pattern: /\bAIza[A-Za-z0-9_-]{35}\b/ },
  { kind: "Slack token", pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/ },
  { kind: "Private key block", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
];
const SENSITIVE_NAME = /(SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY)/i;
const NAMED_LITERAL = /["']?([A-Za-z0-9_]+)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/;
const PLACEHOLDER =
  /^(x+|\*+|\.+|<.*>|your[_-].*|changeme|placeholder|example.*|\$\{.*\}|\$[A-Z_]+|process\.env.*)$/i;
const CONFIG_FILE = /\.(json|jsonc|toml|ya?ml|env)$|(^|\/)\.env(\.[^/]+)?$/;

// Evidence names the kind, length and a short hash so a reader can match
// occurrences without the value ever appearing in output.
const hash8 = (value: string) =>
  NodeCrypto.createHash("sha256").update(value).digest("hex").slice(0, 8);
const fingerprint = (value: string) => `${value.length} chars, sha256:${hash8(value)}`;

const credentialRule: Rule = {
  id: "HI-SECRET-001",
  title: "Credential stored literally in an inspected file",
  run(files) {
    const drafts: Array<Draft> = [];
    for (const file of files.paths) {
      if (/(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock)$|\.example$|\.sample$/.test(file))
        continue;
      const text = files.read(file);
      if (!text) continue;
      text.split("\n").forEach((lineText, i) => {
        const strong = CREDENTIAL_PATTERNS.find((p) => p.pattern.test(lineText));
        const named = NAMED_LITERAL.exec(lineText);
        const weak =
          !strong &&
          CONFIG_FILE.test(file) &&
          named &&
          SENSITIVE_NAME.test(named[1]!) &&
          !PLACEHOLDER.test(named[2]!)
            ? named
            : undefined;
        if (!strong && !weak) return;
        const value = strong ? strong.pattern.exec(lineText)![0] : weak![2]!;
        drafts.push({
          ruleId: this.id,
          title: strong
            ? `${strong.kind} pattern in ${file}`
            : `Literal value assigned to ${weak![1]} in ${file}`,
          subject: strong
            ? `cred:${file}#${strong.kind}:${hash8(value)}`
            : `cred:${file}#${weak![1]}`,
          surface: "secrets",
          category: "credential-exposure",
          owasp: ["ASI03"],
          status: strong ? "confirmed" : "probable",
          evidence: [
            {
              file,
              line: i + 1,
              detail: `${strong ? strong.kind : `value for ${weak![1]}`} (${fingerprint(value)}); value withheld`,
            },
          ],
          preconditions: [
            "The value is a live credential (not verified: it was never used or tested).",
            "The file is readable by agents, CI logs, or anyone with repository access.",
          ],
          impact:
            "Anyone or any agent that reads the file can act with the credential's privileges.",
          fix: {
            summary:
              "Rotate the credential, remove it from the file and its history, and reference it through an environment variable or secret store.",
          },
          verification:
            "Re-run the inspector: the finding disappears and only a reference such as ${VAR} remains.",
          limitations: [
            "Pattern-based: credentials in unusual formats are not detected, and the value was not validated.",
          ],
        });
      });
    }
    return drafts;
  },
};

const PIPE_TO_SHELL = /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/;
const SCRIPT_FILE = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|ps1|pl)$/;

const skillRule: Rule = {
  id: "HI-SKILL-001",
  title: "Skill ships executable content that needs review",
  run(files, { inventory }) {
    const drafts: Array<Draft> = [];
    for (const skill of inventory.skills) {
      const evidence: Array<Evidence> = [];
      let remoteExec = false;
      for (const file of skill.files) {
        const text = files.read(file) ?? "";
        if (SCRIPT_FILE.test(file) || text.startsWith("#!")) {
          evidence.push({
            file,
            detail: "executable script bundled with the skill (not executed)",
          });
        }
        const pipe = PIPE_TO_SHELL.exec(text);
        if (pipe) {
          remoteExec = true;
          evidence.push({
            file,
            ...lineProp(files.lineOf(file, pipe[0])),
            detail: "downloads and pipes remote content to a shell",
          });
        }
      }
      if (skill.allowedTools && /\bBash\b(?!\()/.test(skill.allowedTools)) {
        evidence.push({
          file: `${skill.dir}/SKILL.md`,
          ...lineProp(files.lineOf(`${skill.dir}/SKILL.md`, "allowed-tools")),
          detail: `allowed-tools: ${skill.allowedTools}`,
        });
      }
      if (evidence.length === 0) continue;
      drafts.push({
        ruleId: this.id,
        title: `Skill "${skill.name}" ${remoteExec ? "executes remote content" : "bundles scripts or broad tools"}`,
        subject: `skill:${skill.dir}`,
        surface: "skills",
        category: "skill-supply-chain",
        owasp: ["ASI04", "ASI05"],
        status: remoteExec ? "probable" : "unverifiable",
        evidence,
        preconditions: ["An agent loads the skill and follows its instructions."],
        impact: remoteExec
          ? "Code fetched at run time executes with the agent's shell permissions."
          : "Bundled scripts run with the agent's permissions; their behavior was not analyzed.",
        fix: {
          summary: remoteExec
            ? "Vendor and pin the downloaded script, verify a checksum, or remove the download."
            : "Review the scripts and narrow allowed-tools to the commands the skill needs.",
        },
        verification: "Re-run the inspector after the change and review the remaining evidence.",
        limitations: ["Skill scripts were read as text and never executed."],
      });
    }
    return drafts;
  },
};

export const RULES: ReadonlyArray<Rule> = [
  ciRule,
  mcpRule,
  supplyChainRule,
  permissionRule,
  credentialRule,
  skillRule,
];
