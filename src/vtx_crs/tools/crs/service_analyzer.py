"""Network service analysis tool: port scanning, banner grabbing, service fingerprinting."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from typing import ClassVar

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult

from vtx_crs.core import FindingStatus, Severity, VulnerabilityFinding, get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


from pydantic import BaseModel, Field


class ServiceAnalyzeParams(BaseModel):
    target: str = Field(default="", description="Target host or IP address to scan (e.g. '127.0.0.1', 'localhost').")
    repo_path: str = Field(default="", description="Base repository path.")
    ports: str = Field(
        default="21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017",
        description="Comma-separated list of TCP port numbers to probe.",
    )
    timeout_seconds: int = Field(default=5, description="Per-port socket connection timeout in seconds.")
    mode: str = Field(default="connect", description="Scan mode: 'connect' | 'banner' | 'identify'.")


class ServiceAnalyzerTool(BaseTool[ServiceAnalyzeParams]):
    name = "service_analyze"
    description = (
        "Network Service Reconnaissance (Phase 2): Audits TCP ports, grabs service banners, and fingerprints "
        "daemon versions on local or authorized target systems."
    )
    params = ServiceAnalyzeParams
    mutating = False
    prompt_guidelines = ()

    async def execute(
        self, params: ServiceAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        target = params.target.strip()
        if not target:
            repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
            # Defensive: require explicit target; don't scan repo.name as host (RAPTOR safeguards)
            if not repo.exists():
                return ToolResult(
                    success=False,
                    result="No target specified. Provide target host/IP or a valid repo_path.",
                    ui_summary="Missing target",
                    ui_details="",
                )
            # If repo has no target, default to localhost for local service discovery
            target = "127.0.0.1"
        mode = params.mode.lower().strip()  # connect | banner | identify

        port_list = []
        for p in params.ports.split(","):
            p = p.strip()
            if p.isdigit():
                port_list.append(int(p))

        if not port_list:
            return ToolResult(
                success=False,
                result="No valid ports specified.",
                ui_summary="Invalid ports",
                ui_details="",
            )

        open_ports = []
        banners = {}

        async def probe_port(port: int) -> None:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=params.timeout_seconds
                )
                open_ports.append(port)
                if mode in ("banner", "identify"):
                    banner = await self._grab_banner(reader, writer, port, mode)
                    if banner:
                        banners[port] = banner
                elif mode == "connect":
                    # still try banner for connect but don't require it
                    try:
                        b = await asyncio.wait_for(reader.read(256), timeout=1)
                        if b:
                            banners[port] = b.decode("utf-8", errors="replace").strip()[:100]
                    except Exception:
                        pass
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            except (TimeoutError, ConnectionRefusedError, OSError):
                pass

        tasks = [probe_port(p) for p in port_list]
        await asyncio.gather(*tasks, return_exceptions=True)

        sections = [
            "## Service Analysis",
            f"- Target: {target}",
            f"- Ports scanned: {len(port_list)}",
            f"- Open ports: {len(open_ports)}",
        ]

        if open_ports:
            sections.append("")
            sections.append("### Open Ports")
            for port in sorted(open_ports):
                banner = banners.get(port, "")
                sections.append(f"- {port}/tcp" + (f" - {banner[:100]}" if banner else ""))

        if banners:
            sections.append("")
            sections.append("### Banners")
            for port, banner in sorted(banners.items()):
                sections.append(f"- {port}/tcp: {banner[:200]}")

        # Success semantics: scan succeeded regardless of open count (defensive vs offensive)
        text = "\n".join(sections)
        # Persist open ports as findings for case report
        if open_ports:
            try:
                _c = _case_manager.active_case
                if not _c.repo_path and 'target' in locals():
                    _c.repo_path = str(repo) if 'repo' in locals() else _c.repo_path
                for port in open_ports[:5]:
                    vf = VulnerabilityFinding(
                        title=f"Open port {port}/tcp on {target}",
                        description=f"Service analyzer found open port {port} with banner {banners.get(port,'')[:100]}. Attack surface exposed.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-200",
                        confidence=0.5,
                        file_path=f"{target}:{port}",
                        evidence=[banners.get(port,'')[:300]],
                        remediation="Restrict port exposure, add auth, firewall, or bind to localhost.",
                        status=FindingStatus.OPEN,
                        source="service_analyze",
                        metadata={"port": port, "banner": banners.get(port,'')[:100]},
                    )
                    _c.add_finding(vf)
                _case_manager.save_active()
            except Exception:
                pass

        return ToolResult(
            success=True,
            result=text,
            ui_summary=f"Scanned {len(port_list)} ports — {len(open_ports)} open on {target}",
            ui_details=text,
        )

    async def _grab_banner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, mode: str = "banner"
    ) -> str:
        banner = ""
        try:
            # Service-specific probes (offensive+defensive fingerprinting)
            probe = b"\r\n"
            if port in (80, 8080, 8000, 8443):
                probe = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
            elif port in (22,):
                # SSH banner is server-initiated; just read
                probe = b""
            elif port in (21,):
                probe = b""
            elif port in (25, 587):
                probe = b"EHLO localhost\r\n"
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=2)
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            banner = data.decode("utf-8", errors="replace").strip()
            if mode == "identify" and banner:
                # Light fingerprint
                low = banner.lower()
                if "ssh" in low:
                    banner = f"SSH: {banner[:80]}"
                elif "http" in low:
                    banner = f"HTTP: {banner[:80]}"
                elif "smtp" in low:
                    banner = f"SMTP: {banner[:80]}"
                elif "ftp" in low:
                    banner = f"FTP: {banner[:80]}"
        except Exception:
            pass
        return banner


__all__ = ["ServiceAnalyzerTool"]
