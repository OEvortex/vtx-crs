try:
    from vtx.tui.app import Vtx as _Vtx  # legacy
except (ModuleNotFoundError, ImportError):
    import vtx_crs._compat  # noqa: F401
    from vtx.ui.app import Vtx as _Vtx  # type: ignore
from vtx_crs import config, consume_config_warnings
from vtx_crs.tools import register_with_vtx
from vtx_crs.version import VERSION

from . import branding  # noqa: applies monkey-patches after _LOGO is defined


class Vtx(_Vtx):
    TITLE = "vtx-crs"
    VERSION = VERSION

    def __init__(self, *args, **kwargs):
        register_with_vtx()
        super().__init__(*args, **kwargs)


__all__ = ["Vtx"]
