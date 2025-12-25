"""
Export tools for GhidraMCP.

Provides tools for exporting structures, enums, and function signatures
as C header format for SDK generation.
"""

from .core import mcp, safe_get


@mcp.tool()
def export_structures_as_c(filter: str = None) -> str:
    """
    Export structure definitions as C header format.

    Args:
        filter: Optional substring filter for structure names

    Returns:
        C header code with typedef structs for all matching structures.
        Useful for creating modding SDKs or reimplementations.
    """
    params = {}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("export_structures_as_c", params))


@mcp.tool()
def export_enums_as_c(filter: str = None) -> str:
    """
    Export enum definitions as C header format.

    Args:
        filter: Optional substring filter for enum names

    Returns:
        C header code with enum definitions.
        Useful for creating modding SDKs or reimplementations.
    """
    params = {}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("export_enums_as_c", params))


@mcp.tool()
def export_function_signatures(filter: str = None, offset: int = 0, limit: int = 100) -> str:
    """
    Export function signatures as C declarations.

    Args:
        filter: Optional substring filter for function names
        offset: Pagination offset (default: 0)
        limit: Maximum number of functions (default: 100)

    Returns:
        C function declarations for all matching named functions.
        Useful for creating header files for reimplementation.
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("export_function_signatures", params))
