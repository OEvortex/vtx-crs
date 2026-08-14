"""Environment section for CRS agent system prompt."""

from __future__ import annotations

from datetime import UTC


def build_env_section(cwd: str) -> str:
    from datetime import datetime

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"# Env\n\n- CWD: {cwd}\n- Date: {now}"


__all__ = ["build_env_section"]
