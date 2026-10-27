// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

// Links the skill into the user-level skill folders Claude Code and Codex read.
// `--uninstall` removes only links that point at this package.
const source = NodePath.resolve(import.meta.dirname, "..", "skill", "harness-security-review");
const uninstall = process.argv.includes("--uninstall");
for (const base of [".claude/skills", ".codex/skills"]) {
  const link = NodePath.join(NodeOS.homedir(), base, "harness-security-review");
  const existing = NodeFS.lstatSync(link, { throwIfNoEntry: false });
  const ours = existing?.isSymbolicLink() && NodeFS.readlinkSync(link) === source;
  if (uninstall) {
    if (ours) NodeFS.unlinkSync(link);
    process.stdout.write(`${ours ? "removed" : "left untouched"} ${link}\n`);
  } else if (existing && !ours) {
    process.stdout.write(`skipped ${link}: something else already exists there\n`);
  } else {
    NodeFS.mkdirSync(NodePath.dirname(link), { recursive: true });
    if (!ours) NodeFS.symlinkSync(source, link);
    process.stdout.write(`linked ${link} -> ${source}\n`);
  }
}
