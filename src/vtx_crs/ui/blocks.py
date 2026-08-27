"""Custom Textual tool blocks for CRS tools.

Each block subclasses :class:`vtx.tui.blocks.ToolBlock` and overrides
``_format_header`` / ``_render_result_output`` (and sometimes ``compose``)
to render CRS-specific information that the default block would dump as
plain text. Tool classes attach a block via the ``ui_block`` class attr
(see :func:`register_crs_blocks`).

Layout pattern is consistent across blocks:

  HEADER:    [icon] ToolName  (key=value)
  BODY:      sectioned lines (severity badges, tables, code fences)
  DETAILS:   same as BODY (full ``ui_details`` is preserved for expand)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.app import ComposeResult
from textual.widgets import Label, Static
try:
    from vtx.tui.blocks import ToolBlock
    from vtx.coding_agent.config import config
except (ModuleNotFoundError, ImportError):
    import vtx_crs._compat  # noqa: F401
    try:
        from vtx.ui.blocks import ToolBlock  # type: ignore
    except ImportError:
        from vtx.tui.blocks import ToolBlock  # type: ignore
    try:
        from vtx.config import get_config
        config = get_config()  # type: ignore
    except Exception:
        from vtx_crs.config import config  # type: ignore

if TYPE_CHECKING:
    from vtx.ai.agent.tools import BaseTool


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_color(severity: str) -> str:
    c = config.ui.colors
    return {
        "critical": c.failed,
        "high": c.failed,
        "medium": c.notice,
        "low": c.muted,
        "info": c.muted,
    }.get(severity.lower(), c.muted)


def _kv(prefix: str, key: str, value: Any) -> str:
    """Format a key=value fragment for the call header."""
    v = "" if value is None else str(value)
    if len(v) > 200:
        v = v[:197] + "..."
    return f"{prefix}{key}={v}" if v else ""


def _bullet(text: Text, mark: str = "•") -> Text:
    out = Text()
    out.append(f"  {mark} ", style=config.ui.colors.muted)
    out.append_text(text)
    return out


def _row(*cells: tuple[str, str], indent: str = "    ") -> Text:
    """Render a fixed-width row of (text, color) cells aligned in 2-space gutter."""
    out = Text(indent)
    for i, (text, color) in enumerate(cells):
        if i:
            out.append("  ", style=config.ui.colors.dim)
        out.append(text, style=color)
    return out


def _section(title: str) -> Text:
    out = Text()
    out.append(f"\n  {title}\n", style=f"{config.ui.colors.accent} bold")
    return out


def _fence(text: str, max_lines: int = 18) -> list[Text]:
    """Render a small code-fence-ish block without rich.Panel (so Text stays cheap)."""
    lines = text.splitlines() or [""]
    if len(lines) > max_lines:
        lines = lines[: max_lines - 1] + [f"... ({len(lines) - max_lines + 1} more lines)"]
    out: list[Text] = []
    for line in lines:
        t = Text("    ")
        t.append(line, style=config.ui.colors.dim)
        out.append(t)
    return out



def _collapsed_preview(details: str, max_lines: int = 3) -> Text:
    """Modern collapsed preview — 3 lines + indicator (vtx-crs)."""
    if not details:
        return Text()
    # Strip sections markers and keep first meaningful lines
    raw_lines = [l.rstrip() for l in details.splitlines() if l.strip()]
    # Filter out markdown headers for collapsed compactness
    filtered = [l for l in raw_lines if not l.startswith("---")][:max_lines]
    out = Text()
    for line in filtered:
        # color severity hints
        low = line.lower()
        if any(k in low for k in ("critical", "exploitable", "kev", "crash")):
            style = config.ui.colors.failed
        elif any(k in low for k in ("high", "medium", "warning")):
            style = config.ui.colors.notice
        elif any(k in low for k in ("low", "info", "passed")):
            style = config.ui.colors.muted
        else:
            style = config.ui.colors.dim
        clipped = line[:120] + ("…" if len(line) > 120 else "")
        out.append(f"    {clipped}
", style=style)
    remaining = len(raw_lines) - len(filtered)
    if remaining > 0:
        out.append(f"    ↳ +{remaining} more  ·  ctrl+] to expand
", style=f"{config.ui.colors.accent} italic")
    return out


def _set_tool_attr() -> None:
    """Placeholder for type-checkers; real wiring happens in register_crs_blocks."""


# ---------------------------------------------------------------------------
# Generic fallback used for tools that don't need a custom block.
# ---------------------------------------------------------------------------

class DefaultCrsBlock(ToolBlock):
    """A pass-through ToolBlock used by tools that don't define their own.

    The default ToolBlock already renders the header + the ui_details text
    nicely. This subclass is kept so we can attach a single uniform point
    in :func:`register_crs_blocks` for any tool that opts in by setting
    ``ui_block = DefaultCrsBlock``.
    """


# ---------------------------------------------------------------------------
# Case management
# ---------------------------------------------------------------------------

class CaseManagerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("case_manager", style=f"{colors.accent} bold")
        if self._call_msg:
            result.append("  ")
            result.append(self._call_msg, style=colors.dim)
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result


# ---------------------------------------------------------------------------
# Repository analyzer: language/build/structure summary
# ---------------------------------------------------------------------------

class RepoAnalyzerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("repo_analyze", style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return

        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                rendered.append("\n")
                continue
            if stripped.startswith("Languages:") or stripped.startswith(
                "Build system:"
            ) or stripped.startswith("Test framework:") or stripped.startswith(
                "Entry points:"
            ) or stripped.startswith("VCS:"):
                rendered.append_text(_section(stripped.rstrip(":")))
            elif stripped.startswith("- "):
                rendered.append_text(_bullet(Text(stripped[2:], style=config.ui.colors.fg)))
                rendered.append("\n")
            elif stripped.startswith("  - "):
                t = Text("    ")
                t.append("• ", style=config.ui.colors.muted)
                t.append(stripped[4:], style=config.ui.colors.fg)
                rendered.append_text(t)
                rendered.append("\n")
            else:
                rendered.append(stripped + "\n", style=config.ui.colors.fg)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# We need the Label type from textual for the query_one calls above.
from textual.widgets import Label  # noqa: E402  (placed after RepoAnalyzerBlock to keep header tidy)


# ---------------------------------------------------------------------------
# Build / test / security-validate: command runner blocks
# ---------------------------------------------------------------------------

class _CommandRunnerBlock(ToolBlock):
    """Shared rendering for tools that run a shell command.

    Header shows the command + duration. Body shows exit badge and tail.
    """

    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append(self._name, style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return

        lines = self._ui_details.splitlines()
        rendered = Text()
        # First non-empty line is the human summary; second is the "$ cmd" line.
        i = 0
        while i < len(lines) and not lines[i].strip():
            i += 1
        if i < len(lines):
            rendered.append_text(_section("result"))
            rendered.append(f"    {lines[i]}\n", style=config.ui.colors.fg)
            i += 1
        if i < len(lines) and lines[i].startswith("$ "):
            rendered.append_text(_section("command"))
            rendered.append(f"    {lines[i][2:]}\n", style=config.ui.colors.dim)
            i += 1
        # Remainder is the command's tail.
        tail = [ln for ln in lines[i:] if ln.strip()]
        if tail:
            rendered.append_text(_section("output (tail)"))
            for ln in tail[-30:]:
                rendered.append(f"    {ln}\n", style=config.ui.colors.dim)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class BuildRunnerBlock(_CommandRunnerBlock):
    pass


class TestRunnerBlock(_CommandRunnerBlock):
    pass


class SecurityValidatorBlock(_CommandRunnerBlock):
    pass


# ---------------------------------------------------------------------------
# Vulnerability scanner: severity-bucketed table
# ---------------------------------------------------------------------------

class VulnScannerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.failed)
        result.append("vuln_scan", style=f"{colors.failed} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return

        rendered = Text()
        rendered.append_text(_section("findings"))
        # Lines look like: "<id>  <sev>  <cwe>  <path:line>"
        any_row = False
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped or stripped.startswith("Pattern") or stripped.startswith("---"):
                continue
            parts = stripped.split(None, 3)
            if len(parts) == 4 and not parts[0].startswith("-"):
                fid, sev, cwe, loc = parts
                rendered.append_text(
                    _row(
                        (f"{fid:<10}", config.ui.colors.muted),
                        (f"[{sev.upper():<8}]", _sev_color(sev)),
                        (f"{cwe:<10}", config.ui.colors.muted),
                        (loc, config.ui.colors.fg),
                    )
                )
                rendered.append("\n")
                any_row = True
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        if not any_row:
            rendered.append("    (no findings)\n", style=config.ui.colors.muted)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Dependency scanner: same severity-bucketed style, but data is
# "name version: OSV-id  [SEV]  (CWE) — remediation"
# ---------------------------------------------------------------------------

class DependencyScannerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.notice)
        result.append("dependency_scan", style=f"{colors.notice} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("Note:"):
                rendered.append_text(_section("note"))
                rendered.append(f"    {stripped[5:].strip()}\n", style=config.ui.colors.muted)
            elif stripped.startswith("- "):
                body = stripped[2:]
                # crude sev detection: [high] [medium] ...
                sev = ""
                if "[" in body and "]" in body:
                    sev = body.split("]", 1)[0].rsplit("[", 1)[-1].lower()
                rendered.append_text(
                    _bullet(
                        Text(body, style=_sev_color(sev) if sev else config.ui.colors.fg)
                    )
                )
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# SAST scanner: same look as vuln_scan
# ---------------------------------------------------------------------------

class SastScannerBlock(VulnScannerBlock):
    pass


# ---------------------------------------------------------------------------
# Binary analyzer: file-type + hardening row
# ---------------------------------------------------------------------------

class BinaryAnalyzerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("binary_analyze", style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("- "):
                # "- [HIGH] title: detail"  — show severity badge in color
                body = stripped[2:]
                if body.startswith("["):
                    sev_end = body.find("]")
                    if 0 < sev_end < 12:
                        sev = body[1:sev_end].lower()
                        rest = body[sev_end + 2 :] if sev_end + 1 < len(body) else ""
                        rendered.append_text(
                            _bullet(
                                Text(f"[{sev.upper()}] ", style=_sev_color(sev)).append_text(
                                    Text(rest, style=config.ui.colors.fg)
                                )
                            )
                        )
                        rendered.append("\n")
                        continue
                rendered.append_text(
                    _bullet(Text(body, style=config.ui.colors.fg))
                )
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Dynamic analyzer: syscall summary + tail
# ---------------------------------------------------------------------------

class DynamicAnalyzerBlock(_CommandRunnerBlock):
    pass


# ---------------------------------------------------------------------------
# Service analyzer: open ports list with banners
# ---------------------------------------------------------------------------

class ServiceAnalyzerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("service_analyze", style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        section = ""
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
                section = stripped[3:].lower()
            elif stripped.startswith("### "):
                rendered.append(f"\n  {stripped[4:]}\n", style=f"{config.ui.colors.accent} bold")
            elif stripped.startswith("- "):
                if section.startswith("open ports") or section.startswith("banners"):
                    port, _, banner = stripped[2:].partition(" - ")
                    rendered.append_text(
                        _bullet(
                            Text(port, style=f"{config.ui.colors.success} bold").append(
                                f"  {banner}", style=config.ui.colors.muted
                            )
                        )
                    )
                    rendered.append("\n")
                else:
                    rendered.append_text(_bullet(Text(stripped[2:], style=config.ui.colors.fg)))
                    rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Taint analyzer: file/line/sources/sinks grid
# ---------------------------------------------------------------------------

class TaintAnalyzerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.notice)
        result.append("taint_analyze", style=f"{colors.notice} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped or stripped.startswith("---") or stripped.startswith("FILE "):
                continue
            if stripped.startswith("Taint analysis:"):
                rendered.append_text(_section("flows"))
                continue
            if "  " in stripped and len(stripped.split()) >= 4:
                parts = stripped.split(None, 3)
                if len(parts) == 4:
                    file_, ln, sources, sinks = parts
                    rendered.append_text(
                        _row(
                            (f"{file_:<26}", config.ui.colors.muted),
                            (f"L{ln:<5}", config.ui.colors.accent),
                            (f"src: {sources:<18}", config.ui.colors.notice),
                            (f"sink: {sinks}", config.ui.colors.failed),
                        )
                    )
                    rendered.append("\n")
                    continue
            # fall-through: code lines like "    foo()"
            rendered.append(f"    {stripped.lstrip()}\n", style=config.ui.colors.dim)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Call graph: file -> functions list
# ---------------------------------------------------------------------------

class CallGraphBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("call_graph", style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("- "):
                body = stripped[2:]
                if body.endswith("()"):
                    rendered.append_text(
                        _bullet(
                            Text(body, style=f"{config.ui.colors.accent} bold")
                        )
                    )
                else:
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.dim)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Coverage analyzer: gap table
# ---------------------------------------------------------------------------

class CoverageAnalyzerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("coverage_analyze", style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith(("PATH", "---", "Largest")):
                continue
            if stripped.startswith("Coverage report") or stripped.startswith("No ") or stripped.startswith(
                "Suggested"
            ):
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
            else:
                parts = stripped.split()
                if len(parts) >= 3 and parts[1] in ("lines", "branches"):
                    path, typ, miss = parts[0], parts[1], parts[2]
                    rendered.append_text(
                        _row(
                            (f"{path:<36}", config.ui.colors.fg),
                            (f"{typ:<10}", config.ui.colors.muted),
                            (f"{miss} missing", config.ui.colors.failed),
                        )
                    )
                    rendered.append("\n")
                else:
                    rendered.append(f"    {stripped}\n", style=config.ui.colors.dim)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Crash triager: crash type badge + signals
# ---------------------------------------------------------------------------

class CrashTriagerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.failed)
        result.append("crash_triage", style=f"{colors.failed} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        section = ""
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("Crash type:"):
                rendered.append_text(_section("crash type"))
                rendered.append(
                    f"    {stripped.split(':', 1)[1].strip()}\n",
                    style=f"{config.ui.colors.failed} bold",
                )
            elif stripped.startswith("Faulting location:"):
                rendered.append_text(_section("faulting location"))
                rendered.append(
                    f"    {stripped.split(':', 1)[1].strip() or 'unknown'}\n",
                    style=config.ui.colors.fg,
                )
            elif stripped.startswith("Signals"):
                rendered.append_text(_section("signals"))
            elif stripped.startswith("Remediation"):
                rendered.append_text(_section("remediation"))
            elif stripped.startswith("- ") and (
                section == "signals" or "signals" in rendered.plain.split("\n")[-3:]
            ):
                rendered.append_text(_bullet(Text(stripped[2:], style=config.ui.colors.notice)))
                rendered.append("\n")
            elif stripped[:2] in (" 1", " 2", " 3", " 4"):
                rendered.append(f"    {stripped.strip()}\n", style=config.ui.colors.dim)
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Fuzz harness: campaign stats + crash list
# ---------------------------------------------------------------------------

class FuzzHarnessBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        # Failed block when crashes > 0
        crashed = "crash" in (self._ui_summary or "").lower() and "0 crash" not in (
            self._ui_summary or ""
        ).lower()
        result.append(
            f"{self._icon} ", style=colors.failed if crashed else colors.running
        )
        result.append(
            "fuzz_target", style=f"{colors.failed if crashed else colors.accent} bold"
        )
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("### "):
                rendered.append_text(_section(stripped[4:]))
            elif stripped.startswith("#### "):
                rendered.append(
                    f"\n  {stripped[5:]}\n", style=f"{config.ui.colors.failed} bold"
                )
            elif stripped.startswith("- "):
                body = stripped[2:]
                # Highlight counts (e.g. "Crashes: 3", "Iterations: 100")
                if ":" in body:
                    key, _, val = body.partition(":")
                    val = val.strip()
                    style = (
                        config.ui.colors.failed
                        if any(k in key.lower() for k in ("crash", "hang"))
                        else config.ui.colors.muted
                    )
                    rendered.append_text(
                        _bullet(
                            Text(f"{key}: ", style=config.ui.colors.muted).append(
                                val, style=style
                            )
                        )
                    )
                else:
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.fg)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.dim)

        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Harness / PoC / Mitigation / Symbolic / PatchApply / PatchValidator /
# ReportGenerator: small custom output wrappers around the default text body.
# ---------------------------------------------------------------------------

class _ArtifactBlock(ToolBlock):
    """Shared renderer for tools that emit a short "what was written" summary."""

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith(("Next steps:", "Suggested")):
                rendered.append_text(_section(stripped.rstrip(":")))
            elif stripped.startswith(("  1.", "  2.", "  3.", "  4.")):
                rendered.append(f"    {stripped.strip()}\n", style=config.ui.colors.dim)
            elif stripped.startswith("Output:") or stripped.startswith("Files written:"):
                rendered.append_text(_section(stripped.rstrip(":")))
            elif stripped.startswith("  - "):
                rendered.append_text(_bullet(Text(stripped[4:], style=config.ui.colors.fg)))
                rendered.append("\n")
            elif "written to:" in stripped.lower() or "generated:" in stripped.lower():
                rendered.append(
                    f"    {stripped}\n", style=f"{config.ui.colors.success} bold"
                )
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class HarnessGeneratorBlock(_ArtifactBlock):
    pass


class PovGeneratorBlock(_ArtifactBlock):
    pass


class SymbolicExecutorBlock(_ArtifactBlock):
    pass


class PatchValidatorBlock(_ArtifactBlock):
    pass


class ReportGeneratorBlock(_ArtifactBlock):
    pass


class PatchApplyBlock(ToolBlock):
    """Patch application: shows diff stat + changed files."""

    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        ok = self._success is True
        result.append(
            f"{self._icon} ", style=colors.success if ok else colors.failed
        )
        result.append(
            "patch_apply", style=f"{colors.success if ok else colors.failed} bold"
        )
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            # Modern collapsed — few lines preview (default collapsed)
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        section = ""
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("Changed files:") or stripped.startswith("Would change:"):
                rendered.append_text(_section(stripped.rstrip(":")))
                section = "files"
            elif stripped.startswith("Patch ID:"):
                rendered.append_text(_section("patch"))
                rendered.append(
                    f"    {stripped}\n", style=f"{config.ui.colors.muted} bold"
                )
                section = ""
            elif stripped.startswith("- ") and section == "files":
                rendered.append_text(
                    _bullet(
                        Text(stripped[2:], style=f"{config.ui.colors.accent} bold")
                    )
                )
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class MitigationInjectorBlock(_ArtifactBlock):
    pass


# ---------------------------------------------------------------------------
# Offensive+Defensive unified blocks (RAPTOR + OSS-CRS inspired)
# ---------------------------------------------------------------------------

class ExploitFeasibilityBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        # Offensive -> red if exploitable, defensive green if blocked
        verdict = (self._ui_summary or "").lower()
        is_bad = "exploitable" in verdict and "unverified" not in verdict and "constrained" not in verdict
        is_blocked = "blocked" in verdict
        style = colors.failed if is_bad else colors.success if is_blocked else colors.notice
        result = Text()
        result.append(f"{self._icon} ", style=style)
        result.append("exploit_feasibility", style=f"{style} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("### "):
                rendered.append(f"\n  {stripped[4:]}\n", style=f"{config.ui.colors.accent} bold")
            elif stripped.startswith("- "):
                body = stripped[2:]
                if "exploitable" in body.lower():
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.failed)))
                elif "blocked" in body.lower() or "enabled" in body.lower():
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.success)))
                else:
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.fg)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class WebScannerBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.failed)
        result.append("web_scan", style=f"{colors.failed} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("### "):
                rendered.append(f"\n  {stripped[4:]}\n", style=f"{config.ui.colors.accent} bold")
            elif stripped.startswith("- "):
                body = stripped[2:]
                if any(k in body.lower() for k in ("xss", "sqli", "traversal", "ssti")):
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.failed)))
                else:
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.fg)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class AttackSurfaceBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.notice)
        result.append("attack_surface", style=f"{colors.notice} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("### "):
                rendered.append(f"\n  {stripped[4:]}\n", style=f"{config.ui.colors.accent} bold")
            elif stripped.startswith("- "):
                rendered.append_text(_bullet(Text(stripped[2:], style=config.ui.colors.fg)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class UnifiedScanBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.accent)
        result.append("unified_scan", style=f"{colors.accent} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("### "):
                rendered.append(f"\n  {stripped[4:]}\n", style=f"{config.ui.colors.accent} bold")
            elif stripped.startswith("- "):
                body = stripped[2:]
                if any(k in body.lower() for k in ("critical", "high")):
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.failed)))
                elif "medium" in body.lower():
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.notice)))
                else:
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.fg)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


class OffensiveChainBlock(ToolBlock):
    def _format_header(self, truncate: bool = True) -> Text:
        colors = config.ui.colors
        result = Text()
        result.append(f"{self._icon} ", style=colors.failed)
        result.append("offensive_chain", style=f"{colors.failed} bold")
        if self._ui_summary:
            result.append("  ")
            result.append(self._ui_summary, style=colors.muted)
        return result

    def _render_result_output(self) -> None:
        if not self._ui_details:
            return super()._render_result_output()
        if not self._expanded:
            try:
                output = self.query_one("#tool-output", Label)
            except Exception:
                return
            output.remove_class("-hidden")
            output.add_class("-details")
            self.add_class("-compact")
            self.remove_class("-with-details")
            output.update(_collapsed_preview(self._ui_details or ""))
            return
        try:
            output = self.query_one("#tool-output", Label)
        except Exception:
            return
        rendered = Text()
        for line in self._ui_details.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                rendered.append_text(_section(stripped[3:]))
            elif stripped.startswith("### "):
                rendered.append(f"\n  {stripped[4:]}\n", style=f"{config.ui.colors.accent} bold")
            elif stripped.startswith("- "):
                body = stripped[2:]
                if "exploitable" in body.lower():
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.failed)))
                elif "blocked" in body.lower():
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.success)))
                else:
                    rendered.append_text(_bullet(Text(body, style=config.ui.colors.fg)))
                rendered.append("\n")
            else:
                rendered.append(f"    {stripped}\n", style=config.ui.colors.fg)
        self.remove_class("-compact")
        self.add_class("-with-details")
        output.remove_class("-hidden")
        output.remove_class("-details")
        output.update(rendered)


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------

# Map: tool-name -> block class. Anything not in this map uses the default
# ToolBlock, which is fine for tools whose output is already short text.
# Defensive = blue/notice, Offensive = red/failed, Unified = accent (OSS-CRS + RAPTOR)
_TOOL_BLOCKS: dict[str, type[ToolBlock]] = {
    # Defensive core (merged OP at top)
    "unified_scan": UnifiedScanBlock,
    "attack_surface": AttackSurfaceBlock,
    "binary_analyze": BinaryAnalyzerBlock,
    "build_project": BuildRunnerBlock,
    "call_graph": CallGraphBlock,
    "case_manager": CaseManagerBlock,
    "coverage_analyze": CoverageAnalyzerBlock,
    "dependency_scan": DependencyScannerBlock,
    "repo_analyze": RepoAnalyzerBlock,
    "run_tests": TestRunnerBlock,
    "sast_scan": SastScannerBlock,
    "taint_analyze": TaintAnalyzerBlock,
    "vuln_scan": VulnScannerBlock,
    # Offensive core (red) — merged chain at top
    "offensive_chain": OffensiveChainBlock,
    "crash_triage": CrashTriagerBlock,
    "dynamic_analyze": DynamicAnalyzerBlock,
    "exploit_feasibility": ExploitFeasibilityBlock,
    "fuzz_target": FuzzHarnessBlock,
    "harness_gen": HarnessGeneratorBlock,
    "pov_generate": PovGeneratorBlock,
    "service_analyze": ServiceAnalyzerBlock,
    "symbolic_execute": SymbolicExecutorBlock,
    "web_scan": WebScannerBlock,
    # Remediation (green)
    "generate_report": ReportGeneratorBlock,
    "mitigation_inject": MitigationInjectorBlock,
    "patch_apply": PatchApplyBlock,
    "patch_validate": PatchValidatorBlock,
    "security_validate": SecurityValidatorBlock,
}


def register_crs_blocks(tools_by_name: dict[str, "BaseTool"]) -> None:
    """Attach a custom block class to each CRS tool instance.

    Call once at startup, after the tool list is built. Mutates each
    tool's ``ui_block`` class attribute; safe to call repeatedly.
    """
    for name, block_cls in _TOOL_BLOCKS.items():
        tool = tools_by_name.get(name)
        if tool is not None:
            tool.ui_block = block_cls


__all__ = [
    "AttackSurfaceBlock",
    "BinaryAnalyzerBlock",
    "BuildRunnerBlock",
    "CallGraphBlock",
    "CaseManagerBlock",
    "CoverageAnalyzerBlock",
    "CrashTriagerBlock",
    "DefaultCrsBlock",
    "DependencyScannerBlock",
    "DynamicAnalyzerBlock",
    "ExploitFeasibilityBlock",
    "FuzzHarnessBlock",
    "HarnessGeneratorBlock",
    "MitigationInjectorBlock",
    "OffensiveChainBlock",
    "PatchApplyBlock",
    "PatchValidatorBlock",
    "PovGeneratorBlock",
    "RepoAnalyzerBlock",
    "ReportGeneratorBlock",
    "SastScannerBlock",
    "SecurityValidatorBlock",
    "ServiceAnalyzerBlock",
    "SymbolicExecutorBlock",
    "TaintAnalyzerBlock",
    "TestRunnerBlock",
    "UnifiedScanBlock",
    "VulnScannerBlock",
    "WebScannerBlock",
    "register_crs_blocks",
]
