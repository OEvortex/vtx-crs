"""Network service analysis tool: port scanning, banner grabbing, service fingerprinting."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from typing import ClassVar

from pydantic import BaseModel
from vtx.core.types import ToolResult
from vtx.tools.base import BaseTool

from vtx_crs.core import get_case_manager

from ._common import resolve_repo_path

_case_manager = get_case_manager()


class ServiceAnalyzeParams(BaseModel):
    target: str = ""
    repo_path: str = ""
    ports: str = (
        "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017"
    )
    timeout_seconds: int = 5
    mode: str = "connect"  # "connect" | "banner" | "identify"


class ServiceAnalyzerTool(BaseTool[ServiceAnalyzeParams]):
    name = "service_analyze"
    description = (
        "Network service reconnaissance: connect to TCP ports, grab banners, "
        "identify service versions, and detect open ports on a target host. "
        "Use this for black-box analysis of network-exposed services."
    )
    params = ServiceAnalyzeParams
    mutating = False
    prompt_guidelines = (
        "Use service_analyze to discover open ports and service versions on a target.",
        "Combine with dynamic_analyze to send crafted payloads to identified services.",
        "Be careful: only scan targets you are authorized to test.",
    )

    async def execute(
        self, params: ServiceAnalyzeParams, cancel_event: asyncio.Event | None = None
    ) -> ToolResult:
        target = params.target.strip()
        if not target:
            repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
            target = repo.name if repo.exists() else "localhost"

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
                banner = await self._grab_banner(reader, writer, port)
                if banner:
                    banners[port] = banner
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

        text = "\n".join(sections)
        return ToolResult(
            success=len(open_ports) > 0,
            result=text,
            ui_summary=f"Found {len(open_ports)} open port(s) on {target}",
            ui_details=text,
        )

    async def _grab_banner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int
    ) -> str:
        banner = ""
        try:
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=2)
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            banner = data.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return banner


__all__ = ["ServiceAnalyzerTool"]
