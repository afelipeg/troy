// @effect-diagnostics nodeBuiltinImport:off - Standalone CLI run by agent skills with plain node, outside the Effect runtime.
import * as NodeChildProcess from "node:child_process";
import * as NodePath from "node:path";

// Backs the "Inspeccionar" project action: macOS folder picker, then the
// deterministic inspector. Cancelling the picker ends quietly with no report.
let picked: string;
try {
  picked = NodeChildProcess.execFileSync(
    "osascript",
    ["-e", 'POSIX path of (choose folder with prompt "Proyecto a inspeccionar (solo lectura)")'],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  ).trim();
} catch {
  process.stdout.write(
    "Inspección cancelada: no se eligió ninguna carpeta. No se generó ningún reporte.\n",
  );
  process.exit(0);
}
if (picked === "") {
  process.stdout.write(
    "Inspección cancelada: no se eligió ninguna carpeta. No se generó ningún reporte.\n",
  );
  process.exit(0);
}

const cli = NodePath.resolve(import.meta.dirname, "..", "src", "cli.ts");
const result = NodeChildProcess.spawnSync(process.execPath, [cli, picked], { stdio: "inherit" });
process.exit(result.status ?? 1);
