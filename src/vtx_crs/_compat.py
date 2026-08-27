"""Compatibility shim for vtx 0.2.x flat layout vs legacy vtx-coding-agent namespaced layout."""
import sys

def install_aliases() -> None:
    import importlib
    # Map legacy -> new
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
    }
    # Also top-level packages
    for legacy, new in aliases.items():
        try:
            mod = importlib.import_module(new)
            sys.modules[legacy] = mod
        except Exception:
            pass
    # Ensure parent packages exist
    for pkg in ["vtx.coding_agent", "vtx.tui", "vtx.ai", "vtx.ai.agent"]:
        if pkg not in sys.modules:
            try:
                import types
                sys.modules[pkg] = types.ModuleType(pkg)
            except Exception:
                pass

install_aliases()
