"""Branding monkey-patches for vtx-coding-agent UI elements."""

from __future__ import annotations

import vtx.ui.chat as _vtx_chat
from rich.text import Text
from textual.widgets import Label
from vtx import config

from vtx_crs.ui import launch as _launch
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

    # VTX-CRS logo (same 3-line block, version reads "VTX-CRS vX.Y.Z")
    logo_lines = ("░█░█░███░█░█", "░█░█░░█░░░█░", "░░█░░░█░░█░█")
    for i, line in enumerate(logo_lines):
        info_text.append(line, style=accent)
        if i == len(logo_lines) - 1:
            info_text.append(f" VTX-CRS v{_VERSION}", style=dim)
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
# Exit logo (launch.py :: _LOGO)
# ---------------------------------------------------------------------------
_launch._LOGO = [
    "██╗   ██╗████████╗██╗  ██╗",
    "██║   ██║╚══██╔══╝╚██╗██╔╝",
    "██║   ██║   ██║    ╚███╔╝ ",
    "╚██╗ ██╔╝   ██║    ██╔██╗ ",
    " ╚████╔╝    ██║   ██╔╝ ██╗",
    "  ╚═══╝     ╚═╝   ╚═╝  ╚═╝",
    " VTX-CRS",
]
