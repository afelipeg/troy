// "confirmed" means every precondition was observed in files; it never means exploited.
// "mitigated" means an observed control blocks the path this rule checks; residual
// risk outside that path remains and is listed in the finding.
export type VerificationStatus =
  | "confirmed"
  | "probable"
  | "unverifiable"
  | "mitigated"
  | "dismissed";

// How a relation or fact was established.
export type Basis = "observed" | "inferred" | "unknown";

export interface Evidence {
  readonly file: string;
  readonly line?: number;
  readonly detail: string;
}

export interface ProposedFix {
  readonly summary: string;
  // Unified diff relative to the inspected root. Never applied by the inspector.
  readonly patch?: string;
}

export interface Finding {
  // Stable across runs: derived from ruleId and subject, never from line numbers.
  readonly id: string;
  // What the finding is about (file plus job, server, key or skill), without line numbers.
  readonly subject: string;
  readonly ruleId: string;
  readonly title: string;
  readonly surface: "ci" | "mcp" | "permissions" | "secrets" | "skills";
  readonly category: string;
  readonly owasp: ReadonlyArray<string>;
  readonly status: VerificationStatus;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly preconditions: ReadonlyArray<string>;
  readonly impact: string;
  readonly fix: ProposedFix;
  readonly verification: string;
  readonly limitations: ReadonlyArray<string>;
}

export interface AgentSignal {
  readonly agent: string;
  readonly evidence: ReadonlyArray<Evidence>;
}

export interface SkillEntry {
  readonly name: string;
  readonly dir: string;
  readonly files: ReadonlyArray<string>;
  readonly allowedTools?: string;
}

export interface McpServer {
  readonly name: string;
  readonly client: string;
  readonly file: string;
  readonly line?: number;
  readonly transport: "stdio" | "http" | "unknown";
  readonly command?: string;
  readonly args: ReadonlyArray<string>;
  readonly url?: string;
  // Keys only. Values are never copied out of the file.
  readonly envKeys: ReadonlyArray<string>;
  readonly headerKeys: ReadonlyArray<string>;
}

export interface PermissionSetting {
  readonly client: string;
  readonly file: string;
  readonly line?: number;
  readonly key: string;
  readonly value: string;
}

export interface WorkflowAgentStep {
  readonly job: string;
  readonly line?: number;
  readonly agent: string;
}

export interface WorkflowEntry {
  readonly file: string;
  readonly triggers: ReadonlyArray<string>;
  readonly agentSteps: ReadonlyArray<WorkflowAgentStep>;
  readonly reusableCalls: ReadonlyArray<{ readonly job: string; readonly uses: string }>;
}

export interface CredentialRef {
  readonly name: string;
  readonly file: string;
  readonly line: number;
}

export interface Inventory {
  readonly agents: ReadonlyArray<AgentSignal>;
  readonly instructionFiles: ReadonlyArray<string>;
  readonly skills: ReadonlyArray<SkillEntry>;
  readonly mcpServers: ReadonlyArray<McpServer>;
  readonly permissions: ReadonlyArray<PermissionSetting>;
  readonly workflows: ReadonlyArray<WorkflowEntry>;
  readonly credentialRefs: ReadonlyArray<CredentialRef>;
  readonly filesExamined: number;
  readonly notVerified: ReadonlyArray<string>;
}

export interface PathEdge {
  readonly from: string;
  readonly to: string;
  readonly relation: string;
  readonly basis: Basis;
  readonly evidence?: Evidence;
}

export interface RuleRun {
  readonly id: string;
  readonly title: string;
  readonly findings: number;
}

export interface RunComparison {
  readonly previousRunId: string;
  readonly newIds: ReadonlyArray<string>;
  // The rule no longer detects the pattern. This is not evidence that the risk is gone.
  readonly noLongerDetectedIds: ReadonlyArray<string>;
  readonly persisting: ReadonlyArray<{
    readonly id: string;
    readonly from: VerificationStatus;
    readonly to: VerificationStatus;
  }>;
}

export interface Report {
  readonly schemaVersion: 1;
  // Unique per inspector run; the JSON, Markdown and HTML of one run carry the same value.
  readonly runId: string;
  readonly tool: { readonly name: string; readonly version: string };
  readonly generatedAt: string;
  readonly root: string;
  readonly scope: string;
  // Where the agent session running the inspector was opened relative to the
  // inspected project, and what that does and does not imply. Not a sandbox.
  readonly sessionMode: string;
  // Approval-related configuration detected in the session's project and the evidence
  // behind it. Never a statement of the effective permission mode.
  readonly approvalConfig: string;
  readonly rulesExecuted: ReadonlyArray<RuleRun>;
  readonly inventory: Inventory;
  readonly paths: ReadonlyArray<PathEdge>;
  readonly findings: ReadonlyArray<Finding>;
  // Present when a previous report for the same root was found in the output directory.
  readonly comparison?: RunComparison;
  readonly limitations: ReadonlyArray<string>;
}
