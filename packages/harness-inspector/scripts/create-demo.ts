// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeChildProcess from "node:child_process";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

// Copies the fixture into its own git repository outside this checkout, so the
// dev server's file watcher does not restart when reports are written.
const target = process.argv[2];
if (!target) {
  process.stderr.write("usage: node scripts/create-demo.ts <new-directory>\n");
  process.exit(2);
}
const dir = NodePath.resolve(target);
if (NodeFS.existsSync(dir)) {
  process.stderr.write(`refusing to overwrite existing path: ${dir}\n`);
  process.exit(2);
}
NodeFS.cpSync(NodePath.resolve(import.meta.dirname, "..", "fixtures", "demo-harness"), dir, {
  recursive: true,
  filter: (src) => !src.includes(".harness-inspector"),
});
NodeChildProcess.execFileSync("git", ["init", "-q"], { cwd: dir });
process.stdout.write(`demo harness created at ${dir}\n`);
