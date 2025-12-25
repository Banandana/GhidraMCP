"""
Decompilation and disassembly tools for GhidraMCP.

Provides tools for decompiling functions to C code and disassembling to assembly.
"""

from .core import mcp, safe_get, safe_post


@mcp.tool()
def decompile_function(name: str, max_lines: int = 200) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.

    Args:
        name: The function name to decompile
        max_lines: Maximum number of lines to return (default: 200, 0 for unlimited)

    Returns:
        Decompiled C code (truncated if exceeds max_lines)
    """
    result = safe_post("decompile", name)
    if max_lines > 0:
        lines = result.split('\n')
        if len(lines) > max_lines:
            return '\n'.join(lines[:max_lines]) + f'\n\n... [truncated, showing {max_lines} of {len(lines)} lines]'
    return result


@mcp.tool()
def decompile_function_by_address(address: str, max_lines: int = 200) -> str:
    """
    Decompile a function at the given address.

    Args:
        address: Function address in hex format (e.g. "0x1400010a0")
        max_lines: Maximum number of lines to return (default: 200, 0 for unlimited)

    Returns:
        Decompiled C code (truncated if exceeds max_lines)
    """
    lines = safe_get("decompile_function", {"address": address})
    result = "\n".join(lines)
    if max_lines > 0 and len(lines) > max_lines:
        return '\n'.join(lines[:max_lines]) + f'\n\n... [truncated, showing {max_lines} of {len(lines)} lines]'
    return result


@mcp.tool()
def disassemble_function(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get assembly code (address: instruction; comment) for a function with pagination.

    Args:
        address: Function address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of instructions to return (default: 100)

    Returns:
        List of disassembled instructions
    """
    return safe_get("disassemble_function", {"address": address, "offset": offset, "limit": limit})
