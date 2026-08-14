from __future__ import annotations

from vtx.context import Context, formatted_agent_mds, formatted_git_context, formatted_skills

from .. import config as crs_config
from ..tools import BaseTool
from .env import build_env_section
from .identity import DEFAULT_CRS_BASE
from .tooling import build_tool_guidelines_section


def _resolve_base(override: str | None) -> str:
    if override is not None:
        return override
    configured = crs_config.llm.system_prompt.content
    return configured if configured else DEFAULT_CRS_BASE


def _resolve_git_flag(include_git: bool | None) -> bool:
    if include_git is not None:
        return include_git
    return crs_config.llm.system_prompt.git_context


def build_system_prompt(
    cwd: str,
    context: Context | None = None,
    tools: list[BaseTool] | None = None,
    *,
    base_content: str | None = None,
    include_git_context: bool | None = None,
    extra_instructions: str | None = None,
    extra_instructions_mode: str = "append",
) -> str:
    if context is None:
        context = Context.load(cwd)

    base = _resolve_base(base_content)
    if extra_instructions and extra_instructions_mode == "replace":
        base = extra_instructions
    sections: list[str] = [base]

    if extra_instructions and extra_instructions_mode == "append":
        sections.append(extra_instructions)

    tool_section = build_tool_guidelines_section(tools)
    if tool_section:
        sections.append(tool_section)

    if context.agents_files:
        sections.append(formatted_agent_mds(context.agents_files))

    if context.skills:
        sections.append(formatted_skills(context.skills))

    if _resolve_git_flag(include_git_context):
        git_section = formatted_git_context(cwd)
        if git_section:
            sections.append(git_section)

    sections.append(build_env_section(cwd))

    return "\n\n".join(sections)


__all__ = ["build_system_prompt"]
