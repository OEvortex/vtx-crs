import argparse
import asyncio
import os
import sys

from vtx.llm import PROVIDER_API_BY_NAME

from vtx_crs import config
from vtx_crs.version import VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="vtx-crs — Autonomous Cyber Reasoning System",
        epilog="Example: vtx-crs --repo /path/to/codebase -p 'Analyze this repository, "
        "find and patch vulnerabilities, build, test, and produce a report'",
    )
    parser.add_argument(
        "--repo",
        "-r",
        dest="repo_path",
        help="Path to the target source code repository to analyze (default: current directory)",
    )
    parser.add_argument("--model", "-m", help="Model to use")
    parser.add_argument("--provider", choices=sorted(PROVIDER_API_BY_NAME), help="Provider to use")
    parser.add_argument(
        "--prompt",
        "-p",
        nargs="?",
        const="-",
        default=None,
        help="Run a single prompt non-interactively, then exit "
        "(omit the value or pipe stdin to read the prompt from stdin)",
    )
    parser.add_argument("--api-key", "-k", help="API key")
    parser.add_argument("--base-url", "-u", help="Base URL for API")
    parser.add_argument(
        "--openai-compat-auth",
        choices=("auto", "required", "none"),
        help="Auth mode for OpenAI-compatible endpoints",
    )
    parser.add_argument(
        "--anthropic-compat-auth",
        choices=("auto", "required", "none"),
        help="Auth mode for Anthropic-compatible endpoints",
    )
    parser.add_argument(
        "--insecure-skip-verify",
        action="store_true",
        help="Skip TLS verification (e.g. self-signed certs on local providers)",
    )
    parser.add_argument(
        "--continue",
        "-c",
        action="store_true",
        dest="continue_recent",
        help="Resume the most recent session",
    )
    parser.add_argument(
        "--resume",
        dest="resume_session",
        help="Resume a specific session by ID (full or unique prefix)",
    )
    parser.add_argument(
        "--extension",
        "-e",
        action="append",
        default=[],
        dest="extension_paths",
        metavar="PATH",
        help="Load a Python extension file or package from PATH (repeatable)",
    )
    parser.add_argument(
        "--no-extensions", action="store_true", help="Skip auto-discovered extensions"
    )
    parser.add_argument("--no-agents", action="store_true", help="Skip auto-discovered agents")
    parser.add_argument(
        "--list-agents", action="store_true", help="List all available agents and exit"
    )
    parser.add_argument(
        "--goal", default=None, metavar="OBJECTIVE", help="Set a completion goal before the run."
    )
    parser.add_argument("--version", action="version", version=f"vtx-crs {VERSION}")
    return parser


def _resolve_working_directory(repo_path: str | None) -> str:
    """Change into the target repository so the runtime operates inside it."""
    if not repo_path:
        return os.getcwd()
    target = os.path.abspath(os.path.expanduser(repo_path))
    if not os.path.isdir(target):
        print(f"error: repository path does not exist: {target}", file=sys.stderr)
        raise SystemExit(2)
    os.chdir(target)
    return target


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.prompt is not None and (args.continue_recent or args.resume_session):
        parser.error("-c/--continue and -r/--resume are not supported with -p/--prompt")

    if args.insecure_skip_verify:
        config.llm.tls.insecure_skip_verify = True

    if args.list_agents:
        from vtx.agents import load_all_agents

        loaded, errors = load_all_agents(cwd=os.getcwd(), configured=[])
        if not loaded and not errors:
            print("No agents found.")
        else:
            for a in loaded:
                print(f"{a.definition.name}\t{a.definition.description}\t{a.path}")
        for err in errors:
            print(f"agent error: {err}", file=sys.stderr)
        raise SystemExit(0)

    # Enter the target repository (applies to both headless and TUI modes).
    _resolve_working_directory(args.repo_path)

    if args.prompt is not None:
        from vtx.extensions import load_for_runtime
        from vtx.headless import run_headless

        # Register the CRS tool surface so headless mode exposes it.
        from vtx_crs.tools import register_with_vtx

        register_with_vtx()

        loaded = load_for_runtime(
            cwd=os.getcwd(), extra_paths=args.extension_paths, auto_discover=not args.no_extensions
        )
        for err in loaded.errors:
            print(f"extension error: {err}", file=sys.stderr)

        target_prompt = args.prompt
        if args.repo_path:
            repo_abs = os.path.abspath(os.path.expanduser(args.repo_path))
            target_prompt = (
                f"Analyze the source code repository at: {repo_abs}\n\n"
                f"Run the full cyber-reasoning pipeline: understand the software, discover "
                f"security vulnerabilities, explain them, generate and apply secure patches, "
                f"build, run regression tests, validate the fixes, and produce a professional "
                f"report.\n\n{target_prompt}"
            )

        raise SystemExit(
            asyncio.run(
                run_headless(
                    prompt_arg=target_prompt,
                    model=args.model,
                    provider=args.provider,
                    api_key=args.api_key,
                    base_url=args.base_url,
                    openai_compat_auth_mode=args.openai_compat_auth,
                    anthropic_compat_auth_mode=args.anthropic_compat_auth,
                    loaded_extensions=loaded,
                    goal_objective=args.goal,
                )
            )
        )

    from vtx_crs.ui.launch import run_tui

    run_tui(args)


if __name__ == "__main__":
    main()
