# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
Core module for GhidraMCP - provides MCP instance and HTTP helpers.

This is the foundation module that all other modules import from.
"""

import re
import time
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

# Configuration
DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_TIMEOUT = 120  # 2 minutes for complex analysis operations
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0  # Base delay in seconds

logger = logging.getLogger(__name__)

# Create the MCP server instance - shared by all modules
mcp = FastMCP("ghidra-mcp")

# Global server URL - set by __main__.py or externally
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Connection pooling - reuse connections for better performance
_session = None


def get_session() -> requests.Session:
    """Get or create a persistent HTTP session with connection pooling."""
    global _session
    if _session is None:
        _session = requests.Session()
        # Configure connection pooling
        adapter = HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=Retry(
                total=0,  # We handle retries manually for better control
                backoff_factor=0.5,
            )
        )
        _session.mount('http://', adapter)
        _session.mount('https://', adapter)
    return _session


def set_server_url(url: str):
    """Set the Ghidra server URL."""
    global ghidra_server_url
    ghidra_server_url = url


def safe_get(endpoint: str, params: dict = None, timeout: int = DEFAULT_TIMEOUT,
             max_retries: int = DEFAULT_MAX_RETRIES, retry_delay: float = DEFAULT_RETRY_DELAY) -> list:
    """
    Perform a GET request with optional query parameters and retry logic.

    Args:
        endpoint: API endpoint to call
        params: Query parameters
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts for connection errors
        retry_delay: Base delay between retries (uses exponential backoff)

    Returns:
        List of response lines, or error message list
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)
    last_error = None
    session = get_session()

    for attempt in range(max_retries):
        try:
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = 'utf-8'
            if response.ok:
                return response.text.splitlines()
            else:
                return [f"Error {response.status_code}: {response.text.strip()}"]
        except requests.ConnectionError as e:
            last_error = e
            if attempt < max_retries - 1:
                sleep_time = retry_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Connection error on attempt {attempt + 1}/{max_retries}, retrying in {sleep_time}s: {e}")
                time.sleep(sleep_time)
                continue
        except requests.Timeout as e:
            last_error = e
            if attempt < max_retries - 1:
                sleep_time = retry_delay * (2 ** attempt)
                logger.warning(f"Timeout on attempt {attempt + 1}/{max_retries}, retrying in {sleep_time}s: {e}")
                time.sleep(sleep_time)
                continue
        except Exception as e:
            return [f"Request failed: {str(e)}"]

    return [f"Connection failed after {max_retries} attempts: {last_error}"]


def safe_post(endpoint: str, data: dict | str, timeout: int = DEFAULT_TIMEOUT,
              max_retries: int = DEFAULT_MAX_RETRIES, retry_delay: float = DEFAULT_RETRY_DELAY) -> str:
    """
    Perform a POST request with retry logic.

    Args:
        endpoint: API endpoint to call
        data: POST data (dict or string)
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts for connection errors
        retry_delay: Base delay between retries (uses exponential backoff)

    Returns:
        Response text or error message
    """
    url = urljoin(ghidra_server_url, endpoint)
    last_error = None
    session = get_session()

    for attempt in range(max_retries):
        try:
            if isinstance(data, dict):
                response = session.post(url, data=data, timeout=timeout)
            else:
                response = session.post(url, data=data.encode("utf-8"), timeout=timeout)
            response.encoding = 'utf-8'
            if response.ok:
                return response.text.strip()
            else:
                return f"Error {response.status_code}: {response.text.strip()}"
        except requests.ConnectionError as e:
            last_error = e
            if attempt < max_retries - 1:
                sleep_time = retry_delay * (2 ** attempt)
                logger.warning(f"Connection error on attempt {attempt + 1}/{max_retries}, retrying in {sleep_time}s: {e}")
                time.sleep(sleep_time)
                continue
        except requests.Timeout as e:
            last_error = e
            if attempt < max_retries - 1:
                sleep_time = retry_delay * (2 ** attempt)
                logger.warning(f"Timeout on attempt {attempt + 1}/{max_retries}, retrying in {sleep_time}s: {e}")
                time.sleep(sleep_time)
                continue
        except Exception as e:
            return f"Request failed: {str(e)}"

    return f"Connection failed after {max_retries} attempts: {last_error}"


# =============================================================================
# Core Tools
# =============================================================================

@mcp.tool()
def ping() -> str:
    """
    Quick health check to verify Ghidra server is responding.

    Returns:
        "OK" if server is responding, error message otherwise.

    Use this before starting batch operations to avoid wasted sessions.
    """
    try:
        url = urljoin(ghidra_server_url, "program_info")
        response = requests.get(url, timeout=5)
        if response.ok:
            return "OK - Ghidra server responding"
        return f"ERROR: Server returned {response.status_code}"
    except requests.ConnectionError:
        return "FAIL: Connection refused - is Ghidra running with GhidraMCP plugin?"
    except requests.Timeout:
        return "FAIL: Connection timeout - server may be overloaded"
    except Exception as e:
        return f"FAIL: {str(e)}"


@mcp.tool()
def get_unnamed_count() -> str:
    """
    Get total count of unnamed (FUN_*) functions.

    Returns:
        Count as integer, or error message.

    Use this to calculate accurate offsets for parallel workers.
    Much faster than listing all unnamed functions.
    """
    lines = safe_get("get_analysis_stats", max_retries=1)
    result = "\n".join(lines)

    # Parse the count from analysis stats
    # Expected format includes lines like "Unnamed functions: 12345"
    for line in lines:
        if "unnamed" in line.lower() and "function" in line.lower():
            match = re.search(r'(\d+)', line)
            if match:
                return match.group(1)

    # Fallback: count from get_unnamed_functions with limit=1 to get total
    unnamed = safe_get("get_unnamed_functions", {"offset": 0, "limit": 1}, max_retries=1)
    for line in unnamed:
        if "total" in line.lower() or "count" in line.lower():
            match = re.search(r'(\d+)', line)
            if match:
                return match.group(1)

    return f"Could not parse count from stats: {result[:200]}"


@mcp.tool()
def get_program_info() -> str:
    """
    Get program metadata and architecture information.

    Returns comprehensive information about the loaded binary including:
    - Program name and executable path
    - Language ID (e.g., x86:LE:64:default)
    - Compiler specification
    - Processor and endianness
    - Address size
    - Executable format (PE, ELF, Mach-O, etc.)
    - Image base address
    - Memory size and blocks summary
    - Function and symbol counts
    """
    return "\n".join(safe_get("program_info"))
