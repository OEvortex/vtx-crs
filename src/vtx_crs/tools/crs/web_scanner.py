"""Web reconnaissance scanner: crawl, fingerprint, detect injection points (offensive).

Lightweight port of RAPTOR web scanner: crawls links, tests for XSS/SQLi/SSRF
probes without weaponizing. Designed to be safe to run on authorized targets.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel
from vtx.core.types import ToolResult
try:
    from vtx.coding_agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolResult  # legacy
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolResult  # type: ignore

from vtx_crs.core import get_case_manager
from ._common import resolve_repo_path

_case_manager = get_case_manager()

# Light payloads — non-destructive probes
PAYLOADS = {
    "xss": ["<script>alert(1)</script>", "\"'><svg onload=alert(1)>", "{{7*7}}"],
    "sqli": ["' OR '1'='1", "' OR 1=1--", "1; SELECT 1"],
    "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
    "ssti": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
}


class WebScanParams(BaseModel):
    target_url: str = ""
    repo_path: str = ""
    crawl_depth: int = 1  # 1-3
    check_injection: bool = True
    timeout_seconds: int = 10


class WebScannerTool(BaseTool[WebScanParams]):
    name = "web_scan"
    description = (
        "Web attack-surface scanner (offensive): crawl a URL, fingerprint tech stack, "
        "enumerate forms/params, and probe for injection points (XSS, SQLi, path traversal, SSTI) "
        "using safe canary payloads. Use only on authorized targets."
    )
    params = WebScanParams
    mutating = False
    prompt_guidelines = (
        "Run after repo_analyze/service_analyze when a web target is identified.",
        "Provide target_url (e.g., http://localhost:3000). Depth 1 is safest.",
        "Findings are candidates; confirm by reading source and with security_validate.",
    )

    async def execute(self, params: WebScanParams, cancel_event: asyncio.Event | None = None) -> ToolResult:
        url = params.target_url.strip()
        if not url:
            repo = resolve_repo_path(params.repo_path, _case_manager.active_case.repo_path)
            # Try to infer URL from repo (package.json proxy, docker-compose, etc.)
            inferred = self._infer_url(repo)
            if inferred:
                url = inferred
            else:
                return ToolResult(success=False, result="Provide target_url (e.g., http://localhost:8080) or a repo with web config.", ui_summary="Missing URL", ui_details="")

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        depth = max(1, min(params.crawl_depth, 3))
        # Try to use httpx/aiohttp; fallback to urllib
        try:
            import httpx  # type: ignore

            use_httpx = True
        except ImportError:
            use_httpx = False

        crawl_results = await self._crawl(url, depth, params.timeout_seconds, use_httpx, cancel_event)
        injection_hits: list[dict] = []
        if params.check_injection and crawl_results.get("forms"):
            injection_hits = await self._probe_injection(url, crawl_results["forms"], params.timeout_seconds, use_httpx)

        lines = [
            "## Web Scan (Offensive+Defensive)",
            f"- Target: {url}",
            f"- Crawl depth: {depth}",
            f"- Pages found: {len(crawl_results.get('pages', []))}",
            f"- Forms/params: {len(crawl_results.get('forms', []))}",
            f"- Tech: {crawl_results.get('tech', 'unknown')}",
        ]
        if crawl_results.get("pages"):
            lines.append("")
            lines.append("### Pages")
            for p in crawl_results["pages"][:20]:
                lines.append(f"- {p}")
        if crawl_results.get("forms"):
            lines.append("")
            lines.append("### Forms/Inputs")
            for f in crawl_results["forms"][:15]:
                lines.append(f"- {f}")
        if injection_hits:
            lines.append("")
            lines.append("### Injection Probes (candidate hits)")
            for h in injection_hits:
                lines.append(f"- [{h['type'].upper()}] {h['url']} param={h['param']} payload={h['payload']!r} signal={h['signal']}")
        elif params.check_injection:
            lines.append("")
            lines.append("### Injection Probes: no reflected signals (may still be vulnerable server-side)")
        lines.extend([
            "",
            "### Defensive notes",
            "- Sanitize all reflected params; enforce CSP for XSS.",
            "- Use parameterized queries for SQLi candidates.",
            "- Validate path traversal probes with security_validate.",
        ])
        text = "\n".join(lines)
        return ToolResult(success=True, result=text, ui_summary=f"Web scan: {len(crawl_results.get('pages', []))} pages, {len(injection_hits)} probe hit(s)", ui_details=text)

    def _infer_url(self, repo: Path) -> str | None:
        # Check for common web hints
        for fname in ["package.json", "docker-compose.yml", "docker-compose.yaml", ".env"]:
            p = repo / fname
            if p.exists():
                try:
                    txt = p.read_text(errors="ignore")
                    m = re.search(r"(https?://[^\s\"']+:\d+)", txt)
                    if m:
                        return m.group(1)
                    if "localhost" in txt:
                        mm = re.search(r"localhost:(\d+)", txt)
                        if mm:
                            return f"http://localhost:{mm.group(1)}"
                except OSError:
                    continue
        return None

    async def _crawl(self, base_url: str, depth: int, timeout: int, use_httpx: bool, cancel_event) -> dict:
        pages: list[str] = [base_url]
        forms: list[str] = []
        tech = "unknown"
        visited: set[str] = set()
        queue = [(base_url, 0)]
        while queue:
            url, d = queue.pop(0)
            if url in visited or d > depth:
                continue
            visited.add(url)
            if cancel_event and cancel_event.is_set():
                break
            try:
                html = await self._fetch(url, timeout, use_httpx)
                if not html:
                    continue
                # Tech fingerprint
                low = html.lower()
                if "react" in low or "next.js" in low:
                    tech = "React/Next.js"
                elif "angular" in low:
                    tech = "Angular"
                elif "vue" in low:
                    tech = "Vue"
                elif "django" in low:
                    tech = "Django"
                elif "flask" in low or "jinja" in low:
                    tech = "Flask/Jinja"
                # Forms
                for m in re.finditer(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", html, re.I):
                    forms.append(f"{url} -> {m.group(1)}")
                for m in re.finditer(r"<input[^>]*name=[\"']([^\"']*)[\"']", html, re.I):
                    forms.append(f"{url} input:{m.group(1)}")
                # Links
                if d < depth:
                    for m in re.finditer(r'href=[\"\"]([^\"]+)[\"\"]', html, re.I):
                        href = m.group(1)
                        if href.startswith(("http://", "https://")):
                            full = href
                        elif href.startswith("/"):
                            parsed = urlparse(url)
                            full = f"{parsed.scheme}://{parsed.netloc}{href}"
                        elif href.startswith("#") or href.startswith("mailto:"):
                            continue
                        else:
                            full = urljoin(url, href)
                        if urlparse(full).netloc == urlparse(base_url).netloc and full not in visited:
                            queue.append((full, d + 1))
                            pages.append(full)
            except Exception:
                continue
        return {"pages": pages, "forms": forms, "tech": tech}

    async def _fetch(self, url: str, timeout: int, use_httpx: bool) -> str | None:
        if use_httpx:
            try:
                import httpx  # type: ignore

                async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as c:
                    r = await c.get(url)
                    return r.text if r.status_code < 400 else None
            except Exception:
                return None
        else:
            import urllib.request

            try:
                def _do():
                    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                        return resp.read().decode("utf-8", errors="ignore")
                return await asyncio.to_thread(_do)
            except Exception:
                return None

    async def _probe_injection(self, base_url: str, forms: list[str], timeout: int, use_httpx: bool) -> list[dict]:
        hits: list[dict] = []
        # For each form, try a single canary per type
        for f in forms[:5]:
            # extract param name
            m = re.search(r"input:([A-Za-z0-9_.-]+)", f)
            param = m.group(1) if m else "q"
            action = f.split(" -> ")[-1] if " -> " in f else base_url
            if not action.startswith("http"):
                action = urljoin(base_url, action)
            for vuln_type, payloads in PAYLOADS.items():
                payload = payloads[0]
                try:
                    test_url = f"{action}?{param}={payload}" if "?" not in action else f"{action}&{param}={payload}"
                    body = await self._fetch(test_url, timeout, use_httpx)
                    if body and payload in body:
                        hits.append({"type": vuln_type, "url": test_url, "param": param, "payload": payload, "signal": "reflected"})
                    # Also check error signals for sqli
                    if vuln_type == "sqli" and body and any(k in body.lower() for k in ("sql syntax", "mysql", "sqlite", "postgres", "ora-")):
                        hits.append({"type": vuln_type, "url": test_url, "param": param, "payload": payload, "signal": "sql-error"})
                except Exception:
                    continue
        return hits
