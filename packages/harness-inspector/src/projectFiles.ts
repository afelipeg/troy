// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

const SKIPPED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
  ".harness-inspector",
]);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES = 20_000;

// Read-only view of one project directory. Symlinks are never followed, so the
// inspection cannot leave the selected root.
export class ProjectFiles {
  readonly root: string;
  readonly paths: ReadonlyArray<string>;
  readonly truncated: boolean;
  readonly skippedLarge: ReadonlyArray<string>;
  private readonly cache = new Map<string, string | undefined>();

  constructor(root: string) {
    this.root = NodePath.resolve(root);
    const paths: Array<string> = [];
    const skippedLarge: Array<string> = [];
    let truncated = false;
    const walk = (dir: string) => {
      for (const entry of NodeFS.readdirSync(dir, { withFileTypes: true })) {
        if (paths.length >= MAX_FILES) {
          truncated = true;
          return;
        }
        const abs = NodePath.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIPPED_DIRS.has(entry.name)) walk(abs);
        } else if (entry.isFile()) {
          const rel = NodePath.relative(this.root, abs).split(NodePath.sep).join("/");
          if (NodeFS.statSync(abs).size > MAX_FILE_BYTES) skippedLarge.push(rel);
          else paths.push(rel);
        }
      }
    };
    walk(this.root);
    this.paths = paths.sort();
    this.truncated = truncated;
    this.skippedLarge = skippedLarge;
  }

  has(rel: string): boolean {
    return this.paths.includes(rel);
  }

  read(rel: string): string | undefined {
    if (!this.cache.has(rel)) {
      const buf = NodeFS.readFileSync(NodePath.join(this.root, rel));
      this.cache.set(rel, buf.includes(0) ? undefined : buf.toString("utf8"));
    }
    return this.cache.get(rel);
  }

  lineText(rel: string, line: number): string {
    return (this.read(rel) ?? "").split("\n")[line - 1] ?? "";
  }

  // 1-based line of the first line matching, searching from `fromLine`.
  lineOf(rel: string, match: string | RegExp, fromLine = 1): number | undefined {
    const lines = (this.read(rel) ?? "").split("\n");
    for (let i = fromLine - 1; i < lines.length; i++) {
      const text = lines[i] ?? "";
      if (typeof match === "string" ? text.includes(match) : match.test(text)) return i + 1;
    }
    return undefined;
  }
}
