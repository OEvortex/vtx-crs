"""Compatibility shim for vtx 0.2.x flat layout vs legacy vtx-coding-agent namespaced layout."""
import sys

def install_aliases() -> None:
    import importlib
    # Map legacy -> new (both directions for vtx 0.2.x vs legacy)
    aliases = {
        "vtx.coding_agent.config": "vtx.config",
        "vtx.coding_agent.tools": "vtx.tools",
        "vtx.coding_agent.headless": "vtx.headless",
        "vtx.coding_agent.agents": "vtx.agents",
        "vtx.coding_agent.prompts.builder": "vtx.prompts.builder",
        "vtx.tui.app": "vtx.ui.app",
        "vtx.tui.blocks": "vtx.ui.blocks",
        "vtx.tui.chat": "vtx.ui.chat",
        "vtx.tui.styles": "vtx.ui.styles",
        "vtx.ai.providers": "vtx.llm.providers",
        "vtx.ai.agent.tools": "vtx.tools",
        "vtx.ai.agent.extensions": "vtx.extensions",
        "vtx.core.types": "vtx.core.types",
        # FIX: vtx 0.2.x has vtx.ai.tool_parser but some code expects vtx.llm.tool_parser
        "vtx.llm.tool_parser": "vtx.ai.tool_parser",
        "vtx.llm.providers": "vtx.llm.providers",
        "vtx.llm.models": "vtx.llm.models",
        # reverse aliases for completeness
        "vtx.ai.tool_parser": "vtx.ai.tool_parser",
    }
    # Also top-level packages
    for legacy, new in aliases.items():
        # If legacy == new, skip (already correct)
        if legacy == new:
            continue
        try:
            mod = importlib.import_module(new)
            sys.modules[legacy] = mod
            # Also ensure the parent is a package with the submodule attribute
            parent = legacy.rsplit(".", 1)[0]
            if parent in sys.modules:
                setattr(sys.modules[parent], legacy.rsplit(".", 1)[-1], mod)
        except Exception:
            pass
    # Ensure parent packages exist, but only if they aren't already real packages
    for pkg in ["vtx.coding_agent", "vtx.tui", "vtx.ai", "vtx.ai.agent", "vtx.llm"]:
        if pkg not in sys.modules:
            try:
                importlib.import_module(pkg)
            except (ImportError, ModuleNotFoundError):
                try:
                    import types
                    mod = types.ModuleType(pkg)
                    # mark as package
                    mod.__path__ = []  # type: ignore
                    sys.modules[pkg] = mod
                except Exception:
                    pass
    # Ensure vtx.llm.tool_parser exists even if vtx.llm is a namespace
    if "vtx.llm.tool_parser" not in sys.modules:
        try:
            mod = importlib.import_module("vtx.ai.tool_parser")
            sys.modules["vtx.llm.tool_parser"] = mod
            if "vtx.llm" in sys.modules:
                setattr(sys.modules["vtx.llm"], "tool_parser", mod)
        except Exception:
            pass

install_aliases()
