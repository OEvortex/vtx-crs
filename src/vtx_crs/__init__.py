import vtx_crs._compat  # noqa: F401 — install legacy aliases for vtx 0.2.x

from vtx_crs.config import consume_config_warnings
from vtx_crs.version import VERSION

__all__ = ["VERSION", "consume_config_warnings"]
