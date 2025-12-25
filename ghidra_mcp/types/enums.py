"""
Enum management tools for GhidraMCP.

Provides tools for creating, modifying, and querying enumeration data types.
"""

from ..core import mcp, safe_get, safe_post


@mcp.tool()
def list_enums(offset: int = 0, limit: int = 100) -> list:
    """
    List all enumerations defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of enums with their sizes and value counts
    """
    return safe_get("list_enums", {"offset": offset, "limit": limit})


@mcp.tool()
def get_enum(name: str, category: str = None) -> str:
    """
    Get detailed information about an enum.

    Args:
        name: Enum name to look up
        category: Optional category path

    Returns:
        Detailed enum information including all values with their numeric equivalents
    """
    params = {"name": name}
    if category:
        params["category"] = category
    return "\n".join(safe_get("get_enum", params))


@mcp.tool()
def create_enum(name: str, size: int = 4, category: str = None) -> str:
    """
    Create a new enumeration data type.

    Args:
        name: Name for the new enum
        size: Size in bytes (1, 2, 4, or 8; default: 4)
        category: Optional category path

    Returns:
        Confirmation message with enum details
    """
    params = {"name": name, "size": str(size)}
    if category:
        params["category"] = category
    return safe_post("create_enum", params)


@mcp.tool()
def add_enum_value(enum_name: str, value_name: str, value: str, category: str = None) -> str:
    """
    Add a value to an existing enum.

    Args:
        enum_name: Name of the enum to modify
        value_name: Name for the new value (e.g., "STATUS_SUCCESS")
        value: Numeric value as decimal or hex string (e.g., "0" or "0xFFFFFFFF")
        category: Optional category path

    Returns:
        Confirmation message
    """
    params = {"enum_name": enum_name, "value_name": value_name, "value": value}
    if category:
        params["category"] = category
    return safe_post("add_enum_value", params)


@mcp.tool()
def remove_enum_value(enum_name: str, value_name: str, category: str = None) -> str:
    """
    Remove a value from an enum.

    Args:
        enum_name: Name of the enum to modify
        value_name: Name of the value to remove
        category: Optional category path

    Returns:
        Confirmation message
    """
    params = {"enum_name": enum_name, "value_name": value_name}
    if category:
        params["category"] = category
    return safe_post("remove_enum_value", params)
