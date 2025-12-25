"""
Efficiency and workflow tools for GhidraMCP.

Provides high-efficiency combined operations, parallel worker support,
session management, and metrics for LLM agents.
"""

from .core import mcp, safe_get, safe_post


# =============================================================================
# HEALTH AND METRICS
# =============================================================================

@mcp.tool()
def health() -> str:
    """
    Quick health check to verify Ghidra server is responding.

    Returns:
        "OK" if server is responding, error message otherwise.

    Use this before starting batch operations to avoid wasted sessions.
    Much faster than ping() which uses program_info.
    """
    result = safe_get("health")
    return result[0] if result else "Connection failed"


@mcp.tool()
def get_server_metrics() -> str:
    """
    Get server metrics for monitoring.

    Returns:
        Server uptime, request count, memory usage, and program info.

    Useful for tracking long-running sessions.
    """
    return "\n".join(safe_get("metrics"))


# =============================================================================
# BATCH OPERATIONS
# =============================================================================

@mcp.tool()
def batch_decompile(addresses: str, max_lines: int = 50) -> str:
    """
    Decompile multiple functions in a single call.

    Args:
        addresses: Comma-separated hex addresses (e.g., "0x140001000,0x140001100,0x140001200")
        max_lines: Maximum lines per function (default: 50)

    Returns:
        Combined decompiled code for all functions.

    This is 3-5x faster than calling decompile_function_by_address multiple times
    because it reuses the decompiler instance.
    """
    return safe_post("batch_decompile", {
        "addresses": addresses,
        "max_lines": str(max_lines)
    })


@mcp.tool()
def analyze_function_full(address: str) -> str:
    """
    Combined analysis: decompile + callees + callers + strings in ONE call.

    Args:
        address: Function address in hex format (e.g., "0x140001000")

    Returns:
        Combined analysis including:
        - Function name and whether it's unnamed (FUN_*)
        - Decompiled code (up to 100 lines)
        - Functions it calls (with unnamed highlighted)
        - Functions that call it (with unnamed highlighted)
        - Strings referenced in the function

    This replaces 4-5 separate tool calls with a single efficient operation.
    Use this as the primary analysis tool to avoid multiple round trips.
    """
    return "\n".join(safe_get("analyze_function_full", {"address": address}))


# =============================================================================
# PARALLEL WORKER SUPPORT
# =============================================================================

@mcp.tool()
def get_unnamed_in_range(start: str, end: str, limit: int = 100) -> list:
    """
    Get unnamed functions within an address range.

    Args:
        start: Start address (e.g., "0x140000000")
        end: End address (e.g., "0x141000000")
        limit: Maximum number of functions to return (default: 100)

    Returns:
        List of unnamed functions in the specified range.

    Use this for parallel workers - each worker takes a non-overlapping address range.
    Address ranges are stable (don't change as functions get renamed), unlike offsets.

    Example division for 4 workers on a binary from 0x140000000 to 0x144000000:
        Worker 0: start=0x140000000, end=0x141000000
        Worker 1: start=0x141000000, end=0x142000000
        Worker 2: start=0x142000000, end=0x143000000
        Worker 3: start=0x143000000, end=0x144000000
    """
    return safe_get("get_unnamed_in_range", {
        "start": start,
        "end": end,
        "limit": limit
    })


@mcp.tool()
def claim_function(address: str, worker_id: str) -> str:
    """
    Claim a function for exclusive analysis by a parallel worker.

    Args:
        address: Function address to claim
        worker_id: Unique identifier for this worker

    Returns:
        - "CLAIMED" if successfully claimed
        - "ALREADY_OWNED" if this worker already owns it
        - "ALREADY_CLAIMED by WorkerN" if another worker owns it
        - "FAILED" if claim failed

    Use this to prevent duplicate work when running multiple agents in parallel.
    Claims are stored as bookmarks and persist across restarts.
    """
    return safe_post("claim_function", {
        "address": address,
        "worker_id": worker_id
    })


@mcp.tool()
def release_function(address: str, worker_id: str) -> str:
    """
    Release a previously claimed function.

    Args:
        address: Function address to release
        worker_id: Worker identifier that owns the claim

    Returns:
        "RELEASED" if successful, "NOT_FOUND" if no matching claim exists.

    Call this after successfully renaming a function to allow other workers
    to claim it if needed.
    """
    return safe_post("release_function", {
        "address": address,
        "worker_id": worker_id
    })


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

@mcp.tool()
def checkpoint_session(session_id: str, last_address: str = None, count: str = None) -> str:
    """
    Save session checkpoint for resume after restart.

    Args:
        session_id: Unique session identifier
        last_address: Last processed function address
        count: Number of functions processed

    Returns:
        Confirmation message with checkpoint details.

    Use this periodically during long RE sessions to enable recovery.
    Checkpoints are stored as bookmarks in the program.
    """
    params = {"session_id": session_id}
    if last_address:
        params["last_address"] = last_address
    if count:
        params["count"] = count
    return safe_post("checkpoint_session", params)


@mcp.tool()
def resume_session(session_id: str) -> str:
    """
    Resume from a session checkpoint.

    Args:
        session_id: Session identifier to resume

    Returns:
        - "NEW" if no checkpoint exists (fresh start)
        - "FOUND: last=0x...,count=N,time=..." if checkpoint exists

    Check this at the start of a session to continue where you left off.
    """
    return "\n".join(safe_get("resume_session", {"session_id": session_id}))


# =============================================================================
# PATTERN DETECTION
# =============================================================================

@mcp.tool()
def find_thunks(limit: int = 100) -> list:
    """
    Find thunk functions (single JMP wrappers).

    Args:
        limit: Maximum number of results (default: 100)

    Returns:
        List of thunk functions with their targets.

    Thunks are trivial wrapper functions that just jump to another function.
    These can often be auto-named based on their target (e.g., "thunk_malloc").
    """
    return safe_get("find_thunks", {"limit": limit})


@mcp.tool()
def find_stubs(stub_type: str = "all", limit: int = 100) -> list:
    """
    Find stub functions (return void/0/1 immediately).

    Args:
        stub_type: Filter by type - "void", "return", or "all" (default)
        limit: Maximum number of results (default: 100)

    Returns:
        List of stub functions with instruction count and type.

    Stubs are minimal functions (1-3 instructions) that just return.
    These are often placeholder functions or simple getters/setters.
    """
    return safe_get("find_stubs", {"type": stub_type, "limit": limit})


# =============================================================================
# FUNCTION METRICS
# =============================================================================

@mcp.tool()
def get_function_metrics(address: str) -> str:
    """
    Get function complexity metrics.

    Args:
        address: Function address in hex format

    Returns:
        Metrics including:
        - Instruction count
        - Basic block count
        - Cyclomatic complexity
        - Parameter and variable counts
        - Caller/callee counts
        - Body size in bytes
        - Complexity rating (Low/Moderate/High/Very High)

    Use this to prioritize analysis of complex functions over trivial ones.
    """
    return "\n".join(safe_get("get_function_metrics", {"address": address}))


@mcp.tool()
def get_function_signature_details(address: str) -> str:
    """
    Get detailed function signature for better naming hints.

    Args:
        address: Function address in hex format

    Returns:
        Detailed signature including:
        - Return type
        - Calling convention
        - Parameters with types
        - Is thunk/external flags
        - Stack frame size
        - C++ method detection hints

    Use this to understand function interfaces for better naming.
    """
    return "\n".join(safe_get("get_function_signature", {"address": address}))


# =============================================================================
# PROGRESS TRACKING
# =============================================================================

@mcp.tool()
def get_naming_progress_stats() -> str:
    """
    Get current progress on function naming.

    Returns:
        - Total functions vs named vs unnamed
        - Percentage complete
        - Encouragement message

    Use periodically to track progress without reading external files.
    """
    return "\n".join(safe_get("get_naming_progress"))


# =============================================================================
# UNDO/REDO
# =============================================================================

@mcp.tool()
def undo() -> str:
    """
    Undo the last modification.

    Returns:
        "Undo successful" or "Nothing to undo"

    Use this to revert mistakes. Ghidra maintains a full undo history.
    """
    return "\n".join(safe_get("undo"))


@mcp.tool()
def redo() -> str:
    """
    Redo the last undone modification.

    Returns:
        "Redo successful" or "Nothing to redo"

    Use this after undo to restore changes.
    """
    return "\n".join(safe_get("redo"))
