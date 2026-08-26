from vtx.ai.agent.tools import BaseTool
from vtx.core.types import ToolDefinition

from .crs.binary_analyzer import BinaryAnalyzerTool
from .crs.build_runner import BuildRunnerTool
from .crs.case_manager import CaseManagerTool
from .crs.dependency_scanner import DependencyScannerTool
from .crs.dynamic_analyzer import DynamicAnalyzerTool
from .crs.fuzz_harness import FuzzHarnessTool
from .crs.patch_apply import PatchApplyTool
from .crs.repo_analyzer import RepoAnalyzerTool
from .crs.report_generator import ReportGeneratorTool
from .crs.security_validator import SecurityValidatorTool
from .crs.service_analyzer import ServiceAnalyzerTool
from .crs.test_runner import TestRunnerTool
from .crs.vuln_scanner import VulnScannerTool

CRS_TOOLS = [
    RepoAnalyzerTool(),
    VulnScannerTool(),
    DependencyScannerTool(),
    PatchApplyTool(),
    BuildRunnerTool(),
    TestRunnerTool(),
    SecurityValidatorTool(),
    ReportGeneratorTool(),
    CaseManagerTool(),
    BinaryAnalyzerTool(),
    DynamicAnalyzerTool(),
    FuzzHarnessTool(),
    ServiceAnalyzerTool(),
]

all_tools = list(CRS_TOOLS)
tools_by_name = {tool.name: tool for tool in all_tools}

DEFAULT_TOOLS = [tool.name for tool in all_tools]

DENIED_TOOLS: set[str] = set()


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
    """Register the CRS-only tool surface into vtx runtime registries."""
    import vtx.coding_agent.tools as vtx_tools
    import vtx.tui.app as vtx_app

    vtx_tools.tools_by_name.clear()
    vtx_tools.tools_by_name.update(tools_by_name)
    vtx_tools.DEFAULT_TOOLS = list(DEFAULT_TOOLS)
    vtx_app.DEFAULT_TOOLS = list(DEFAULT_TOOLS)


__all__ = [
    "CRS_TOOLS",
    "DEFAULT_TOOLS",
    "DENIED_TOOLS",
    "BaseTool",
    "BinaryAnalyzerTool",
    "BuildRunnerTool",
    "CaseManagerTool",
    "DependencyScannerTool",
    "DynamicAnalyzerTool",
    "FuzzHarnessTool",
    "PatchApplyTool",
    "RepoAnalyzerTool",
    "ReportGeneratorTool",
    "SecurityValidatorTool",
    "ServiceAnalyzerTool",
    "TestRunnerTool",
    "VulnScannerTool",
    "get_tool",
    "get_tools",
    "get_tools_with_extensions",
    "get_tool_definitions",
    "register_with_vtx",
    "all_tools",
    "tools_by_name",
]
