import vtx_crs._compat  # noqa: F401 — legacy aliases

try:
    from vtx.ai.agent.tools import BaseTool  # legacy
    from vtx.core.types import ToolDefinition
except (ModuleNotFoundError, ImportError):
    from vtx.tools import BaseTool  # type: ignore
    from vtx.core.types import ToolDefinition  # type: ignore

from .crs.attack_surface import AttackSurfaceTool
from .crs.binary_analyzer import BinaryAnalyzerTool
from .crs.build_runner import BuildRunnerTool
from .crs.call_graph import CallGraphTool
from .crs.case_manager import CaseManagerTool
from .crs.coverage_analyzer import CoverageAnalyzerTool
from .crs.crash_triager import CrashTriagerTool
from .crs.dependency_scanner import DependencyScannerTool
from .crs.dynamic_analyzer import DynamicAnalyzerTool
from .crs.exploit_feasibility import ExploitFeasibilityTool
from .crs.fuzz_harness import FuzzHarnessTool
from .crs.harness_generator import HarnessGeneratorTool
from .crs.mitigation_injector import MitigationInjectorTool
from .crs.offensive_chain import OffensiveChainTool
from .crs.patch_apply import PatchApplyTool
from .crs.patch_validator import PatchValidatorTool
from .crs.pov_generator import PovGeneratorTool
from .crs.repo_analyzer import RepoAnalyzerTool
from .crs.report_generator import ReportGeneratorTool
from .crs.sast_scanner import SastScannerTool
from .crs.security_validator import SecurityValidatorTool
from .crs.service_analyzer import ServiceAnalyzerTool
from .crs.symbolic_executor import SymbolicExecutorTool
from .crs.taint_analyzer import TaintAnalyzerTool
from .crs.test_runner import TestRunnerTool
from .crs.unified_scan import UnifiedScanTool
from .crs.vuln_scanner import VulnScannerTool
from .crs.web_scanner import WebScannerTool

CRS_TOOLS = [
    # Defensive core — OP merged
    RepoAnalyzerTool(),
    AttackSurfaceTool(),
    UnifiedScanTool(),  # merged: vuln_scan + sast_scan + taint_analyze (3-in-1, OP)
    VulnScannerTool(),  # keep for granular use, but unified_scan is preferred
    SastScannerTool(),  # alias, shares engine
    DependencyScannerTool(),  # OP: OSV + KEV + EPSS + pip-audit/npm audit
    TaintAnalyzerTool(),
    CallGraphTool(),
    CoverageAnalyzerTool(),
    # Offensive core (RAPTOR-style) — OP merged chain
    OffensiveChainTool(),  # merged: crash_triage + exploit_feasibility + pov_generate (3-in-1, OP)
    CrashTriagerTool(),
    BinaryAnalyzerTool(),
    DynamicAnalyzerTool(),
    FuzzHarnessTool(),
    HarnessGeneratorTool(),
    PovGeneratorTool(),
    SymbolicExecutorTool(),
    ServiceAnalyzerTool(),
    WebScannerTool(),
    ExploitFeasibilityTool(),
    # Remediation (OSS-CRS libCRS-style)
    PatchApplyTool(),
    PatchValidatorTool(),
    MitigationInjectorTool(),
    BuildRunnerTool(),
    TestRunnerTool(),
    SecurityValidatorTool(),
    ReportGeneratorTool(),
    CaseManagerTool(),
]

all_tools = list(CRS_TOOLS)
tools_by_name = {tool.name: tool for tool in all_tools}

DEFAULT_TOOLS = [tool.name for tool in all_tools]

DENIED_TOOLS: set[str] = {"edit", "write", "skill"}


def get_tools(names: list[str]) -> list[BaseTool]:
    return [tool for tool in all_tools if tool.name in names]


def get_tool(tool_name: str) -> BaseTool | None:
    return tools_by_name.get(tool_name)


def get_tools_with_extensions(
    default_names: list[str], extension_tools: list[BaseTool] | None = None
) -> list[BaseTool]:
    ext_list = list(extension_tools or [])
    result: list[BaseTool] = []
    seen: set[str] = set()

    for name in default_names:
        tool = tools_by_name.get(name)
        if tool is not None and name not in seen:
            result.append(tool)
            seen.add(name)

    for tool in ext_list:
        if tool.name in seen:
            continue
        result.append(tool)
        seen.add(tool.name)

    return result


def get_tool_definitions(tools: list[BaseTool]) -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name=tool.name,
            description=tool.description,
            parameters=tool.params.model_json_schema(),
        )
        for tool in tools
    ]


def register_with_vtx() -> None:
    """Register the CRS tool surface into vtx runtime registries.

    Keeps vtx built-in tools (bash, read, web, ask_user, etc.) available
    alongside the CRS-specific tools.
    """
    import vtx.coding_agent.tools as vtx_tools
    import vtx.tui.app as vtx_app

    # Start from vtx built-ins, then overlay CRS tools so both surfaces
    # are available to the agent.
    merged_tools_by_name = dict(vtx_tools.tools_by_name)
    merged_tools_by_name.update(tools_by_name)
    vtx_tools.tools_by_name = merged_tools_by_name

    merged_defaults = list(vtx_tools.DEFAULT_TOOLS)
    for name in DEFAULT_TOOLS:
        if name not in merged_defaults:
            merged_defaults.append(name)
    merged_defaults = [name for name in merged_defaults if name not in DENIED_TOOLS]
    vtx_tools.DEFAULT_TOOLS = merged_defaults
    vtx_app.DEFAULT_TOOLS = merged_defaults

    # Attach the custom CRS tool blocks. Done after vtx's own registers
    # so we win on the same `tools_by_name` dict.
    from vtx_crs.ui.blocks import register_crs_blocks

    register_crs_blocks(merged_tools_by_name)


__all__ = [
    "CRS_TOOLS",
    "DEFAULT_TOOLS",
    "DENIED_TOOLS",
    "BaseTool",
    "AttackSurfaceTool",
    "BinaryAnalyzerTool",
    "BuildRunnerTool",
    "CallGraphTool",
    "CaseManagerTool",
    "CoverageAnalyzerTool",
    "CrashTriagerTool",
    "DependencyScannerTool",
    "DynamicAnalyzerTool",
    "ExploitFeasibilityTool",
    "FuzzHarnessTool",
    "HarnessGeneratorTool",
    "MitigationInjectorTool",
    "OffensiveChainTool",
    "PatchApplyTool",
    "PatchValidatorTool",
    "PovGeneratorTool",
    "RepoAnalyzerTool",
    "ReportGeneratorTool",
    "SastScannerTool",
    "SecurityValidatorTool",
    "ServiceAnalyzerTool",
    "SymbolicExecutorTool",
    "TaintAnalyzerTool",
    "TestRunnerTool",
    "UnifiedScanTool",
    "VulnScannerTool",
    "WebScannerTool",
    "all_tools",
    "get_tool",
    "get_tool_definitions",
    "get_tools",
    "get_tools_with_extensions",
    "register_with_vtx",
    "tools_by_name",
]
