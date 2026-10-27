#!/usr/bin/env node
// Entry point next to SKILL.md. Node resolves this import through the real
// path, so it works when the skill directory is symlinked into ~/.claude/skills.
import "../../src/cli.ts";
