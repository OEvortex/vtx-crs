from vtx.coding_agent.prompts.builder import build_system_prompt as _vtx_build_system_prompt
from vtx.coding_agent.config import config as crs_config

from ..tools import BaseTool
from .identity import DEFAULT_CRS_BASE


def build_system_prompt(
    cwd: str,
    context=None,
    tools: list[BaseTool] | None = None,
    *,
    base_content: str | None = None,
    include_git_context: bool | None = None,
    extra_instructions: str | None = None,
    extra_instructions_mode: str = "append",
    skills=None,
) -> str:
    if base_content is None:
        base_content = DEFAULT_CRS_BASE
    if include_git_context is None:
        include_git_context = crs_config.llm.system_prompt.git_context
    return _vtx_build_system_prompt(
        cwd,
        context=context,
        tools=tools,
        base_content=base_content,
        include_git_context=include_git_context,
        extra_instructions=extra_instructions,
        extra_instructions_mode=extra_instructions_mode,
        skills=skills,
    )


__all__ = ["build_system_prompt"]
