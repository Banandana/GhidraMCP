"""
Structure management tools for GhidraMCP.

Provides tools for creating, modifying, and querying structure data types.
"""

from ..core import mcp, safe_get, safe_post


@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List all structures defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of structures with their sizes and field counts
    """
    return safe_get("list_structures", {"offset": offset, "limit": limit})


@mcp.tool()
def get_structure(name: str) -> str:
    """
    Get detailed information about a structure.

    Args:
        name: Structure name to look up

    Returns:
        Detailed structure layout including all fields with offsets, sizes, and types
    """
    return "\n".join(safe_get("get_structure", {"name": name}))


@mcp.tool()
def create_struct(name: str, category: str = None, size: int = 0) -> str:
    """
    Create a new structure data type.

    Args:
        name: Name for the new structure
        category: Optional category path (e.g., "MyStructures")
        size: Initial size in bytes (default: 0 for auto-sizing)

    Returns:
        Confirmation message with structure details
    """
    params = {"name": name, "size": str(size)}
    if category:
        params["category"] = category
    return safe_post("create_struct", params)


@mcp.tool()
def add_struct_member(struct_name: str, field_name: str, data_type: str,
                      offset: int = -1, category: str = None, comment: str = None) -> str:
    """
    Add a member field to an existing structure.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name for the new field
        data_type: Data type for the field (e.g., "int", "DWORD", "char[32]")
        offset: Byte offset for the field (-1 to append at end)
        category: Optional category path if structure is in a category
        comment: Optional comment for the field

    Returns:
        Confirmation message with field details
    """
    params = {
        "struct_name": struct_name,
        "field_name": field_name,
        "data_type": data_type,
        "offset": str(offset)
    }
    if category:
        params["category"] = category
    if comment:
        params["comment"] = comment
    return safe_post("add_struct_member", params)


@mcp.tool()
def remove_struct_member(struct_name: str, field_name: str = None,
                         offset: int = -1, category: str = None) -> str:
    """
    Remove a member from a structure.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the field to remove (optional if offset provided)
        offset: Byte offset of the field to remove (optional if field_name provided)
        category: Optional category path if structure is in a category

    Returns:
        Confirmation message
    """
    params = {"struct_name": struct_name, "offset": str(offset)}
    if field_name:
        params["field_name"] = field_name
    if category:
        params["category"] = category
    return safe_post("remove_struct_member", params)


@mcp.tool()
def clear_struct(struct_name: str, category: str = None) -> str:
    """
    Remove all members from a structure.

    Args:
        struct_name: Name of the structure to clear
        category: Optional category path if structure is in a category

    Returns:
        Confirmation message with number of fields cleared
    """
    params = {"struct_name": struct_name}
    if category:
        params["category"] = category
    return safe_post("clear_struct", params)


@mcp.tool()
def resize_struct(struct_name: str, new_size: int, category: str = None) -> str:
    """
    Resize an existing structure to a new size.

    Use this when you need to add fields at offsets beyond the current structure size.
    For example, if a structure is 1 byte but you need to add a field at offset 4,
    first resize the structure to at least 8 bytes.

    Args:
        struct_name: Name of the structure to resize
        new_size: New size in bytes (must be >= 0)
        category: Optional category path if structure is in a category

    Returns:
        Confirmation message with old and new size
    """
    params = {"struct_name": struct_name, "new_size": str(new_size)}
    if category:
        params["category"] = category
    return safe_post("resize_struct", params)


@mcp.tool()
def delete_struct(struct_name: str, category: str = None) -> str:
    """
    Delete a structure data type.

    Use this to completely remove a structure so it can be recreated with
    a different size or layout. This is useful when a structure was created
    as a stub (e.g., 1 byte) and needs to be recreated properly.

    Args:
        struct_name: Name of the structure to delete
        category: Optional category path if structure is in a category

    Returns:
        Confirmation message
    """
    params = {"struct_name": struct_name}
    if category:
        params["category"] = category
    return safe_post("delete_struct", params)
