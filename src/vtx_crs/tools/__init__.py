from vtx.core.types import ToolDefinition
from vtx.tools.ask_user import AskUserTool
from vtx.tools.base import BaseTool
from vtx.tools.bash import BashTool
from vtx.tools.edit import EditTool
from vtx.tools.find import FindTool
from vtx.tools.grep import GrepTool
from vtx.tools.read import ReadTool
from vtx.tools.skill import SkillTool
from vtx.tools.task import TaskTool
from vtx.tools.web import WebFetchTool, WebSearchTool
from vtx.tools.write import WriteTool

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

__all__ = [
    "DEFAULT_TOOLS",
    "AskUserTool",
    "BaseTool",
    "BashTool",
    "BuildRunnerTool",
    "CaseManagerTool",
    "DependencyScannerTool",
    "EditTool",
    "FindTool",
    "GrepTool",
    "PatchApplyTool",
    "ReadTool",
    "RepoAnalyzerTool",
    "ReportGeneratorTool",
    "SecurityValidatorTool",
    "SkillTool",
    "TaskTool",
    "TestRunnerTool",
    "VulnScannerTool",
    "WebFetchTool",
    "WebSearchTool",
    "WriteTool",
    "get_tool",
    "get_tool_definitions",
    "get_tools",
    "get_tools_with_extensions",
    "register_with_vtx",
]

all_tools: list[BaseTool] = [
    ReadTool(),
    EditTool(),
    WriteTool(),
    BashTool(),
    FindTool(),
    GrepTool(),
    SkillTool(),
    WebFetchTool(),
    WebSearchTool(),
    AskUserTool(),
    TaskTool(),
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

DENIED_TOOLS: set[str] = {"edit", "grep"}
# edit and grep are disabled for CRS; use patch_apply and find instead

tools_by_name: dict[str, BaseTool] = {tool.name: tool for tool in all_tools}
DEFAULT_TOOLS: list[str] = [
    # vtx-coding-agent built-ins (source reading, editing, execution).
    "read",
    "write",
    "bash",
    "find",
    "skill",
    "fetch_webpage",
    "web_search",
    "ask_user",
    "task",
    # CRS pipeline tools.
    "repo_analyze",
    "vuln_scan",
    "dependency_scan",
    "patch_apply",
    "build_project",
    "run_tests",
    "security_validate",
    "generate_report",
    "case_manager",
    "binary_analyze",
    "dynamic_analyze",
    "fuzz_target",
    "service_analyze",
]


def _denied(tool: BaseTool) -> bool:
    return tool.name in DENIED_TOOLS


def get_tools(names: list[str]) -> list[BaseTool]:
    return [tool for tool in all_tools if tool.name in names and not _denied(tool)]


def get_tool(tool_name: str) -> BaseTool | None:
    t = tools_by_name.get(tool_name)
    return None if t is not None and _denied(t) else t


def get_tools_with_extensions(
    default_names: list[str], extension_tools: list[BaseTool] | None = None
) -> list[BaseTool]:
    ext_list = list(extension_tools or [])
    result: list[BaseTool] = []
    overrides: dict[str, BaseTool] = {t.name: t for t in ext_list}

    for name in default_names:
        if name in DENIED_TOOLS:
            continue
        if name in overrides:
            result.append(overrides.pop(name))
        else:
            builtin = tools_by_name.get(name)
            if builtin is not None:
                result.append(builtin)

    for tool in ext_list:
        if _denied(tool):
            continue
        if tool.name in {t.name for t in result}:
            continue
        result.append(tool)

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
    """Register the CRS tool surface into the vtx runtime registries.

    ``vtx.headless.run_headless`` resolves tools from ``vtx.tools`` at call
    time, so registering our tools there (plus its module-level DEFAULT_TOOLS
    list) makes the CRS tools available in headless mode too.
    """
    import vtx.headless as vtx_headless
    import vtx.tools as vtx_tools

    for tool in all_tools:
        vtx_tools.tools_by_name[tool.name] = tool
    vtx_tools.DEFAULT_TOOLS = list(DEFAULT_TOOLS)
    vtx_headless.DEFAULT_TOOLS = list(DEFAULT_TOOLS)  # pyright: ignore[reportPrivateImportUsage]
