import type { ProjectFiles } from "./projectFiles.ts";

const CONTEXT = 2;

// Unified diff for one edit at a 1-based line: either replace that line or
// insert lines after it. Output applies with `git apply` from the root.
export function linePatch(
  files: ProjectFiles,
  file: string,
  line: number,
  edit: { readonly replaceWith: string } | { readonly insertAfter: ReadonlyArray<string> },
): string | undefined {
  const text = files.read(file);
  if (text === undefined) return undefined;
  const lines = text.split("\n");
  if (text.endsWith("\n")) lines.pop();
  const index = line - 1;
  if (index < 0 || index >= lines.length) return undefined;

  const start = Math.max(0, index - CONTEXT);
  const before = lines.slice(start, index).map((l) => ` ${l}`);
  const target = lines[index]!;
  const end = Math.min(lines.length, index + 1 + CONTEXT);
  const after = lines.slice(index + 1, end).map((l) => ` ${l}`);

  const body =
    "replaceWith" in edit
      ? [...before, `-${target}`, `+${edit.replaceWith}`, ...after]
      : [...before, ` ${target}`, ...edit.insertAfter.map((l) => `+${l}`), ...after];
  const oldCount = end - start;
  const newCount = "replaceWith" in edit ? oldCount : oldCount + edit.insertAfter.length;
  return [
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -${start + 1},${oldCount} +${start + 1},${newCount} @@`,
    ...body,
    "",
  ].join("\n");
}
