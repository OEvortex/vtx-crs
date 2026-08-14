from vtx.context._xml import escape_xml
from vtx.core.scratchpad import get_scratchpad_dir, init_scratchpad, is_scratchpad_path

from vtx_crs.config import (
    AVAILABLE_BINARIES,
    CONFIG_DIR_NAME,
    Config,
    consume_config_warnings,
    get_agents_dir,
    get_config,
    get_config_dir,
    reload_config,
    reset_config,
    set_colored_tool_badge,
    set_config,
    set_git_context,
    set_model_provider_filter,
    set_notifications_enabled,
    set_permissions_mode,
    set_show_welcome_shortcuts,
    set_theme,
    set_thinking_lines,
    update_available_binaries,
)


class _ConfigProxy(Config):
    def __init__(self) -> None:
        pass

    def __getattr__(self, name: str):
        return getattr(get_config(), name)


config = _ConfigProxy()

__all__ = [
    "AVAILABLE_BINARIES",
    "CONFIG_DIR_NAME",
    "Config",
    "config",
    "consume_config_warnings",
    "escape_xml",
    "get_agents_dir",
    "get_config",
    "get_config_dir",
    "get_scratchpad_dir",
    "init_scratchpad",
    "is_scratchpad_path",
    "reload_config",
    "reset_config",
    "set_colored_tool_badge",
    "set_config",
    "set_git_context",
    "set_model_provider_filter",
    "set_notifications_enabled",
    "set_permissions_mode",
    "set_show_welcome_shortcuts",
    "set_theme",
    "set_thinking_lines",
    "update_available_binaries",
]
