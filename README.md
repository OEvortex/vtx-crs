# vtx-crs

Autonomous Cyber Reasoning System (CRS) built on `vtx-coding-agent`.

Not a chatbot — an autonomous AI software-security engineer. Point it at an unknown source
repository and it runs the full pipeline with little or no human intervention:

1. **Read** the repository — maps languages, build system, test framework, entry points, structure.
2. **Understand** the software — traces data flows from inputs to dangerous sinks.
3. **Discover vulnerabilities** — CWE-mapped static pattern analysis + keyless OSV dependency scanning.
4. **Explain** why they exist — precise data-flow explanations with CWE, severity, and confidence.
5. **Generate secure patches** — minimal, correct unified diffs.
6. **Apply patches** — validated application with rollback-safe dry runs.
7. **Build** the software — auto-detected build commands.
8. **Run regression tests** — auto-detected test suites, pass/fail summaries.
9. **Security validation** — PoC/check commands proving the vulnerability is gone.
10. **Prove the fix** — pre/post validation comparison recorded in the case.
11. **Professional report** — Markdown + JSON report with full audit trail.

## Install

```bash
uv run python -m pip install -e .
```

## Usage

```bash
# Headless autonomous analysis of a repository
vtx-crs --repo /path/to/codebase -p "Analyze this repository, find and fix security vulnerabilities, build, test, and produce a report"

# Interactive TUI inside the target repository
vtx-crs --repo /path/to/codebase

# Operate on the current directory (no --repo)
vtx-crs -p "Audit this project for vulnerabilities and patch them"
```

### Keyless-first

The static analyzer and the OSV dependency scanner need no API keys. Use your configured LLM
provider (e.g. `-m <model> --provider <provider>` or the interactive `/model` picker) to drive
the reasoning loop.

### The CRS tool surface

Built-in coding tools (`read`, `write`, `edit`, `find`, `grep`, `bash`, `task`, `web`, …) are
combined with CRS-specific tools:

| Tool | Purpose |
|------|---------|
| `repo_analyze` | Map an unknown codebase (languages, build, tests, entry points) |
| `vuln_scan` | CWE-mapped static pattern scan (injection, XSS, path traversal, secrets, …) |
| `dependency_scan` | Known-vulnerability lookup for pinned deps via the OSV API |
| `patch_apply` | Validate + apply unified diffs, track patches in the case |
| `build_project` | Auto-detect and run the build command |
| `run_tests` | Auto-detect and run the regression test suite |
| `security_validate` | Run PoC/check commands to prove a fix |
| `generate_report` | Write the final professional report (MD + JSON) |
| `case_manager` | Create/switch/list cases; audit trail per engagement |

## License

AGPL-3.0
