"""
Batch operation tools for GhidraMCP.

Provides tools for renaming multiple functions and setting multiple comments
in single operations.
"""

from .core import mcp, safe_get, safe_post


@mcp.tool()
def batch_rename_functions(renames: str) -> str:
    """
    Rename multiple functions in a single operation.

    Args:
        renames: JSON array of rename operations, each with:
            - "address": Function address
            - "name": New function name
            Example: '[{"address":"0x140001000","name":"init_player"},{"address":"0x140001100","name":"update_player"}]'

    Returns:
        Results for each rename operation (success/failure).
        More efficient than individual rename calls.
    """
    return safe_post("batch_rename_functions", {"renames": renames})


@mcp.tool()
def batch_set_comments(comments: str) -> str:
    """
    Set multiple comments in a single operation.

    Args:
        comments: JSON array of comment operations, each with:
            - "address": Address for comment
            - "comment": Comment text
            - "type": Optional, "decompiler" or "disassembly" (default: "decompiler")
            Example: '[{"address":"0x140001000","comment":"Initialize player state"},{"address":"0x140001050","comment":"Load config","type":"disassembly"}]'

    Returns:
        Results for each comment operation.
    """
    return safe_post("batch_set_comments", {"comments": comments})
