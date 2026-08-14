"""Tool usage guidelines section for CRS agent system prompt."""

from __future__ import annotations

from ..tools import BaseTool


def build_tool_guidelines_section(tools: list[BaseTool] | None = None) -> str:
    if not tools:
        return ""
    lines = ["# Tool usage"]
    for tool in tools:
        if tool.prompt_guidelines:
            lines.append(f"- {tool.name}:")
            for g in tool.prompt_guidelines:
                lines.append(f"  - {g}")
    if len(lines) == 1:
        return ""
    return "\n".join(lines)


__all__ = ["build_tool_guidelines_section"]
