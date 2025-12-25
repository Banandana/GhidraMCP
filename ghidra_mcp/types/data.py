"""
Data type and label tools for GhidraMCP.

Provides tools for managing data types, labels, and data at addresses.
"""

from ..core import mcp, safe_get, safe_post


@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List all data types defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)
        category: Optional category filter (e.g., "windows", "struct")

    Returns:
        List of data types with their paths, types, and sizes
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_data_types", params)


@mcp.tool()
def get_data_by_label(label: str) -> str:
    """
    Get information about data at a labeled address.

    Args:
        label: The label/symbol name to look up

    Returns:
        Data information including address, type, size, value, and reference count.
        If exact match not found, suggests similar labels.
    """
    return "\n".join(safe_get("get_data_by_label", {"label": label}))


@mcp.tool()
def get_data_by_labels(labels: list[str]) -> str:
    """
    Get information about data at multiple labeled addresses (batch lookup).

    Args:
        labels: List of label/symbol names to look up
            Example: ["g_PlayerInstance", "g_GameState", "g_SaveManager"]

    Returns:
        Combined data information for all labels, with each result separated.
        More efficient than calling get_data_by_label multiple times.
    """
    results = []
    for label in labels:
        results.append(f"=== {label} ===")
        results.extend(safe_get("get_data_by_label", {"label": label}))
        results.append("")
    return "\n".join(results)


@mcp.tool()
def set_data_type(address: str, data_type: str, length: int = -1) -> str:
    """
    Set the data type at a specific address.

    Args:
        address: Address in hex format (e.g., "0x1400010a0")
        data_type: Data type to apply (e.g., "int", "DWORD", "char[100]", structure name)
        length: Optional length for variable-length types

    Returns:
        Confirmation message with data details
    """
    params = {"address": address, "data_type": data_type}
    if length >= 0:
        params["length"] = str(length)
    return safe_post("set_data_type", params)
