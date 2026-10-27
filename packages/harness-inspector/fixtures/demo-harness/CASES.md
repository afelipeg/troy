# Expected cases

| Case                                                                  | Files                                    | Expected status                                    |
| --------------------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------- |
| Risk: comment text interpolated into a CI agent with write token      | `.github/workflows/agent-triage.yml`     | confirmed                                          |
| Similar but gated: same agent limited to OWNER/MEMBER/COLLABORATOR    | `.github/workflows/agent-maintainer.yml` | mitigated (residual risk remains)                  |
| Incomplete: untrusted trigger delegates to a remote reusable workflow | `.github/workflows/agent-review.yml`     | unverifiable                                       |
| Risk: filesystem MCP server allowed on `/`                            | `.mcp.json`                              | probable (effective scope depends on client roots) |
| Benign: filesystem MCP server scoped to `./docs`, pinned version      | `.mcp.json`                              | no finding                                         |
| Incomplete: remote MCP server                                         | `.mcp.json`                              | unverifiable                                       |
| Literal value under a credential-named key (fictitious)               | `.mcp.json`                              | probable                                           |
| Skill that pipes a download into a shell                              | `.claude/skills/release-notes`           | probable                                           |
| Benign permissions: acceptEdits plus one specific command             | `.claude/settings.json`                  | no finding                                         |
