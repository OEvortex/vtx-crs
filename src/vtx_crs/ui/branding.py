"""Branding monkey-patches for vtx-coding-agent UI elements."""

from __future__ import annotations

try:
    import vtx.tui.chat as _vtx_chat  # legacy
    import vtx.tui.styles as _vtx_styles  # legacy
    from vtx.coding_agent.config import config  # legacy
    from vtx.tui.blocks import ToolBlock as _ToolBlock  # legacy
except (ModuleNotFoundError, ImportError):
    import vtx_crs._compat  # noqa: F401
    try:
        import vtx.ui.chat as _vtx_chat  # type: ignore
        import vtx.ui.styles as _vtx_styles  # type: ignore
        from vtx.ui.blocks import ToolBlock as _ToolBlock  # type: ignore
    except ImportError:
        import vtx.tui.chat as _vtx_chat  # type: ignore
        import vtx.tui.styles as _vtx_styles  # type: ignore
        from vtx.tui.blocks import ToolBlock as _ToolBlock  # type: ignore
    try:
        from vtx.config import get_config
        config = get_config()  # type: ignore
    except Exception:
        from vtx_crs.config import config  # type: ignore
from rich.text import Text
from textual.widgets import Label

from vtx_crs.version import VERSION as _VERSION

# ---------------------------------------------------------------------------
# Startup logo (chat.py :: ChatLog.add_session_info)
# ---------------------------------------------------------------------------
_ORIGINAL_ADD_SESSION_INFO = _vtx_chat.ChatLog.add_session_info


def _patched_add_session_info(self: _vtx_chat.ChatLog, version: str) -> None:
    """Replacement that injects VTX-CRS branding."""
    info_text = Text()
    accent = config.ui.colors.accent
    dim = config.ui.colors.dim
    muted = config.ui.colors.muted

    # VTX-CRS logo (same 3-line block, version reads "VTX-CRS vX.Y.Z" + offensive+defensive tag)
    logo_lines = ("░█░█░███░█░█", "░█░█░░█░░░█░", "░░█░░░█░░█░█")
    for i, line in enumerate(logo_lines):
        info_text.append(line, style=accent)
        if i == len(logo_lines) - 1:
            info_text.append(f" VTX-CRS v{_VERSION}", style=dim)
        info_text.append("\n")
    info_text.append("  Offensive + Defensive Cyber Reasoning", style=dim)
    info_text.append("\n")
    info_text.append("  [", style=dim)
    info_text.append("●", style=config.ui.colors.failed)
    info_text.append(" offensive", style=dim)
    info_text.append("  ", style=dim)
    info_text.append("●", style=config.ui.colors.notice)
    info_text.append(" defensive", style=dim)
    info_text.append("  ", style=dim)
    info_text.append("●", style=config.ui.colors.success)
    info_text.append(" remediation", style=dim)
    info_text.append("]", style=dim)
    info_text.append("\n")

    if config.ui.show_welcome_shortcuts:
        info_text.append("\n")

        shortcut_rows = (
            (
                ("/", "slash commands"),
                ("@", "files/dirs"),
                ("tab", "complete paths"),
                ("↑/↓", "history"),
            ),
            (
                ("shift+tab", "switch agent"),
                ("esc", "to interrupt"),
                ("shift+enter", "add newline"),
            ),
            (
                ("ctrl+c", "clear input"),
                ("ctrl+c x2", "exit"),
                ("enter", "queue"),
                ("alt+enter", "steer"),
            ),
            (
                ("↑/↓", "select queue"),
                ("ctrl+t", "cycle thinking"),
                ("ctrl+shift+t", "toggle thinking"),
            ),
        )

        for row_idx, row in enumerate(shortcut_rows):
            for item_idx, (key, desc) in enumerate(row):
                if item_idx > 0:
                    info_text.append(" • ", style=dim)
                info_text.append(key, style=muted)
                info_text.append(f" {desc}", style=dim)
            if row_idx < len(shortcut_rows) - 1:
                info_text.append("\n")

    info_text.rstrip()

    info_label = Label(info_text)
    info_label.add_class("session-info")
    self.mount(info_label, before=0)


_vtx_chat.ChatLog.add_session_info = _patched_add_session_info  # ty:ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# Tool block styling
# ---------------------------------------------------------------------------

_ORIGINAL_GET_STYLES = _vtx_styles.get_styles


def _patched_get_styles() -> str:
    """Append CRS-branded tool block CSS to the base vtx styles."""
    base = _ORIGINAL_GET_STYLES()
    colors = config.ui.colors

    return base + f"""
/* CRS branded tool blocks */
.tool-block {{
    background: {colors.editor};
    border-left: 3px solid {colors.running};
    padding: 0;
    margin-top: 1;
}}

.tool-block.-compact {{
    margin-top: 0;
}}

.tool-block #tool-header {{
    padding: 0 1;
    background: transparent;
}}

.tool-block #tool-output {{
    padding: 0 1 1 1;
    color: {colors.dim};
}}

.tool-block.-with-details #tool-output {{
    padding: 0 1 1 1;
}}

/* State-driven accents */
.tool-block.-pending {{
    border-left-color: {colors.running};
    background: {colors.editor};
}}

.tool-block.-success {{
    border-left-color: {colors.success};
    background: {colors.editor};
}}

.tool-block.-error {{
    border-left-color: {colors.failed};
    background: {colors.editor};
}}
"""


_vtx_styles.get_styles = _patched_get_styles  # ty:ignore[invalid-assignment]


# ---------------------------------------------------------------------------
# Tag CRS tool blocks so they can be targeted specifically
# ---------------------------------------------------------------------------

_ORIGINAL_TOOL_BLOCK_INIT = _ToolBlock.__init__


def _patched_tool_block_init(self: _ToolBlock, *args, **kwargs) -> None:
    _ORIGINAL_TOOL_BLOCK_INIT(self, *args, **kwargs)
    if self.__class__.__module__ and self.__class__.__module__.startswith(
        "vtx_crs.ui.blocks"
    ):
        self.add_class("crs-block")


_ToolBlock.__init__ = _patched_tool_block_init  # ty:ignore[method-assign]
