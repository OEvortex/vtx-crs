"""Compat layer for vtx config — supports both vtx.coding_agent (legacy) and vtx 0.2.x flat."""
try:
    from vtx.coding_agent.config import (  # type: ignore
        AVAILABLE_BINARIES,
        CONFIG_DIR_NAME,
        CURRENT_CONFIG_VERSION,
        Config,
        add_recent_model,
        config,
        consume_config_warnings,
        get_agents_dir,
        get_config,
        get_config_dir,
        get_last_selected,
        get_recent_models,
        reload_config,
        reset_config,
        set_colored_tool_badge,
        set_config,
        set_git_context,
        set_last_selected,
        set_model_provider_filter,
        set_notifications_enabled,
        set_permissions_mode,
        set_show_welcome_shortcuts,
        set_theme,
        set_thinking_lines,
        update_available_binaries,
    )
except (ModuleNotFoundError, ImportError):
    import vtx.config as _vc  # vtx 0.2.x flat layout

    # Re-export what exists, with shims for legacy names
    AVAILABLE_BINARIES = getattr(_vc, "AVAILABLE_BINARIES", set())
    CONFIG_DIR_NAME = getattr(_vc, "CONFIG_DIR_NAME", ".vtx")
    CURRENT_CONFIG_VERSION = getattr(_vc, "CURRENT_CONFIG_VERSION", 11)
    Config = getattr(_vc, "Config", getattr(_vc, "ConfigSchema", object))
    add_recent_model = getattr(_vc, "add_recent_model", lambda *a, **kw: None)
    # legacy had `config` singleton; new has get_config() factory
    try:
        config = _vc.get_config()  # type: ignore
    except Exception:
        config = None
    consume_config_warnings = getattr(_vc, "consume_config_warnings", lambda: [])
    get_agents_dir = getattr(_vc, "get_agents_dir", lambda: _vc.get_config_dir() / "agents" if hasattr(_vc, "get_config_dir") else None)
    get_config = getattr(_vc, "get_config", lambda: config)
    get_config_dir = getattr(_vc, "get_config_dir", lambda: None)
    get_last_selected = getattr(_vc, "get_last_selected", lambda: None)
    get_recent_models = getattr(_vc, "get_recent_models", lambda: [])
    reload_config = getattr(_vc, "reload_config", lambda: config)
    reset_config = getattr(_vc, "reset_config", lambda: None)
    set_colored_tool_badge = getattr(_vc, "set_colored_tool_badge", lambda x: None)
    set_config = getattr(_vc, "set_config", lambda x: None)
    set_git_context = getattr(_vc, "set_git_context", lambda x: None)
    set_last_selected = getattr(_vc, "set_last_selected", lambda *a, **kw: None)
    set_model_provider_filter = getattr(_vc, "set_model_provider_filter", lambda x: None)
    set_notifications_enabled = getattr(_vc, "set_notifications_enabled", lambda x: None)
    set_permissions_mode = getattr(_vc, "set_permissions_mode", lambda x: None)
    set_show_welcome_shortcuts = getattr(_vc, "set_show_welcome_shortcuts", lambda x: None)
    set_theme = getattr(_vc, "set_theme", lambda x: None)
    set_thinking_lines = getattr(_vc, "set_thinking_lines", lambda x: None)
    update_available_binaries = getattr(_vc, "update_available_binaries", lambda: None)
    # AVAILABLE_BINARIES may be computed via function
    try:
        if not AVAILABLE_BINARIES and hasattr(_vc, "_detect_available_binaries"):
            AVAILABLE_BINARIES = _vc._detect_available_binaries()  # type: ignore
    except Exception:
        pass

__all__ = [
    "AVAILABLE_BINARIES",
    "CONFIG_DIR_NAME",
    "CURRENT_CONFIG_VERSION",
    "Config",
    "add_recent_model",
    "config",
    "consume_config_warnings",
    "get_agents_dir",
    "get_config",
    "get_config_dir",
    "get_last_selected",
    "get_recent_models",
    "reload_config",
    "reset_config",
    "set_colored_tool_badge",
    "set_config",
    "set_git_context",
    "set_last_selected",
    "set_model_provider_filter",
    "set_notifications_enabled",
    "set_permissions_mode",
    "set_show_welcome_shortcuts",
    "set_theme",
    "set_thinking_lines",
    "update_available_binaries",
]
