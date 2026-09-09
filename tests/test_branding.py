"""Tests for VTX-CRS UI branding monkey-patches and expand/collapse."""

from __future__ import annotations

import inspect

import vtx.tui.styles as _vtx_styles


def test_branding_injects_crs_tool_block_styles() -> None:
    """Importing branding must append CRS-specific CSS to the base styles."""
    from vtx_crs.ui import branding  # noqa: F401 - triggers monkey-patches

    styles = _vtx_styles.get_styles()
    assert "/* CRS branded tool blocks */" in styles
    assert ".tool-block.-pending" in styles
    assert ".tool-block.-success" in styles
    assert ".tool-block.-error" in styles
    assert ".tool-block #tool-header" in styles
    assert ".tool-block #tool-output" in styles
    assert "border-left" in styles
    assert "padding: 0 1 1 1" in styles


def test_crs_block_class_added_to_crs_tool_blocks() -> None:
    """CRS ToolBlock subclasses must receive the ``crs-block`` CSS class."""
    from vtx_crs.ui.blocks import UnifiedScanBlock

    class _FakeUnifiedScanBlock(UnifiedScanBlock):
        __module__ = "vtx_crs.ui.blocks"

    block = _FakeUnifiedScanBlock.__new__(_FakeUnifiedScanBlock)
    # We cannot call __init__ without a full textual app, but we can invoke
    # the patched init directly and verify the class is added.
    from vtx.tui.blocks import ToolBlock

    ToolBlock.__init__(block, name="unified_scan")
    assert block.has_class("crs-block")


def test_non_crs_block_does_not_get_crs_class() -> None:
    """Non-CRS ToolBlock instances must NOT receive the ``crs-block`` class."""
    from vtx.tui.blocks import ToolBlock

    class _FakeBlock(ToolBlock):
        __module__ = "some.other.module"

    block = _FakeBlock.__new__(_FakeBlock)
    ToolBlock.__init__(block, name="bash")
    assert not block.has_class("crs-block")


def test_crs_blocks_respect_expand_collapse() -> None:
    """Every custom CRS block must check ``self._expanded`` before rendering."""
    from vtx_crs.ui import blocks as crs_blocks

    custom_blocks = [
        crs_blocks.RepoAnalyzerBlock,
        crs_blocks.BuildRunnerBlock,
        crs_blocks.TestRunnerBlock,
        crs_blocks.DependencyScannerBlock,
        crs_blocks.BinaryAnalyzerBlock,
        crs_blocks.ServiceAnalyzerBlock,
        crs_blocks.CallGraphBlock,
        crs_blocks.CoverageAnalyzerBlock,
        crs_blocks.FuzzHarnessBlock,
        crs_blocks.DynamicAnalyzerBlock,
        crs_blocks.HarnessGeneratorBlock,
        crs_blocks.SymbolicExecutorBlock,
        crs_blocks.PatchValidatorBlock,
        crs_blocks.ReportGeneratorBlock,
        crs_blocks.MitigationInjectorBlock,
        crs_blocks.PatchApplyBlock,
        crs_blocks.AttackSurfaceBlock,
        crs_blocks.UnifiedScanBlock,
        crs_blocks.OffensiveChainBlock,
        crs_blocks.WebScannerBlock,
        crs_blocks.CaseManagerBlock,
    ]

    for block_cls in custom_blocks:
        source = inspect.getsource(block_cls._render_result_output)
        assert "if not self._expanded:" in source, (
            f"{block_cls.__name__}._render_result_output does not check self._expanded"
        )
        assert "return super()._render_result_output()" in source, (
            f"{block_cls.__name__}._render_result_output does not fall back to base class"
        )
