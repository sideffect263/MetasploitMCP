import asyncio
import contextlib
import logging
import os
import shlex # Used for quoting, though not strictly needed when shell=False
import subprocess
from typing import List, Dict, Any, Optional, Tuple

# Third-party Libraries
import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from mcp.server.fastmcp import FastMCP
# --- Import MsfConsole ---
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError, MsfConsole
# -------------------------
from starlette.applications import Starlette
from mcp.server.sse import SseServerTransport
from starlette.requests import Request
from starlette.routing import Mount, Route

# --- Configuration ---

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("metasploit_mcp_server")

# --- Metasploit Client Setup ---

# Global variable to hold the client instance (initialized at startup)
_msf_client_instance: Optional[MsfRpcClient] = None

def safe_get_data(result: Any, default: str = "") -> str:
    """
    Safely extract 'data' field from a result object that might be a dictionary or something else.

    Args:
        result: Object that might be a dictionary with a 'data' field or some other type
        default: Default value to return if data can't be extracted

    Returns:
        The 'data' value if available, string representation of result, or default value
    """
    if isinstance(result, dict) and 'data' in result:
        return result.get('data', default)
    elif hasattr(result, 'data'):
        # Handle objects with a data attribute
        try:
            return str(result.data)
        except Exception as e:
            logger.warning(f"Error accessing data attribute: {e}")
    elif hasattr(result, 'read'):
        # Handle objects with a read method (like MsfConsole)
        try:
            # Let's not read here unless absolutely necessary, as it might interfere
            logger.debug("safe_get_data encountered readable object, returning str representation.")
            return str(result) # Return string representation instead of reading
        except Exception as e:
            logger.warning(f"Error reading/stringifying readable object: {e}")
    elif result is not None:
        try:
            return str(result)
        except Exception as e:
            logger.warning(f"Error converting result to string: {e}")
    return default

async def run_command_safely(console: Any, cmd: str, execution_timeout: Optional[int] = None) -> str:
    """
    Safely run a command on a Metasploit console and return the output.

    This helper handles different console implementations and return types.

    Args:
        console: The Metasploit console object
        cmd: The command to run
        execution_timeout: Optional specific timeout for this command's execution phase.

    Returns:
        The command output as a string
    """
    try:
        logger.debug(f"Running console command: {cmd}")

        # Prefer write/read if available, seems more standard for interaction
        if hasattr(console, 'write') and hasattr(console, 'read'):
            logger.debug("Using console.write/read method")
            await asyncio.to_thread(console.write, cmd + '\n') # Ensure newline

            # --- Improved Read Logic ---
            output_buffer = ""
            start_time = asyncio.get_event_loop().time()

            # Determine read timeout
            # Default is 10s, increased for run/exploit, overridden by parameter if provided
            read_timeout = 10
            is_long_command = cmd.strip().startswith("run") or cmd.strip().startswith("exploit")
            if is_long_command:
                read_timeout = 60
            if execution_timeout is not None:
                 # Let the explicit timeout override defaults
                 read_timeout = execution_timeout
                 logger.debug(f"Using specified execution timeout: {read_timeout}s")


            check_interval = 0.2 # Seconds between checks

            while True:
                await asyncio.sleep(check_interval)
                # Read available data without blocking indefinitely
                chunk_result = await asyncio.to_thread(console.read)
                chunk_data = ""
                if isinstance(chunk_result, dict) and 'data' in chunk_result:
                    chunk_data = chunk_result.get('data','')

                if chunk_data:
                    #logger.debug(f"Read chunk: {chunk_data}")
                    output_buffer += chunk_data
                    # Reset timer if we get data, maybe command is still running
                    start_time = asyncio.get_event_loop().time()
                elif (asyncio.get_event_loop().time() - start_time) > read_timeout:
                    logger.debug(f"Read timeout ({read_timeout}s) reached for command '{cmd}' with no new data.")
                    break # Exit loop after timeout with no new data
                # Check busy status - might help break loop faster if console reports idle
                try:
                    # Only check busy status if it's likely relevant (e.g., after some initial wait)
                    if (asyncio.get_event_loop().time() - start_time) > 1.0:
                         is_busy = await asyncio.to_thread(console.is_busy)
                         # logger.debug(f"Console busy status: {is_busy}")
                         if not is_busy:
                             logger.debug("Console reported not busy, ending read loop.")
                             break
                except Exception as busy_err:
                    # is_busy might not always be reliable or available
                    # Don't log warning every check interval, maybe just once?
                    # logger.warning(f"Could not check console busy status: {busy_err}")
                    pass # Ignore busy check errors silently for now

            logger.debug(f"Final output for '{cmd}':\n{output_buffer.strip()}")
            return output_buffer.strip()
            # --- End Improved Read Logic ---

        # Fallback: Try run_single_command (less reliable for output)
        elif hasattr(console, 'run_single_command'):
            logger.warning(f"Using console.run_single_command for '{cmd}' (may not capture full output).")
            # Note: run_single_command might not be easily timeout-controllable here
            result = await asyncio.to_thread(lambda: console.run_single_command(cmd))
            logger.debug(f"run_single_command result: {result}")
            # Attempt a quick read just in case output is buffered
            read_result = await asyncio.to_thread(console.read)
            return safe_get_data(read_result) # Hope output was captured

        else:
            logger.error(f"Console object {type(console)} has no usable command execution method (write/read or run_single_command).")
            raise TypeError("Unsupported console object type for command execution.")

    except Exception as e:
        logger.exception(f"Error executing command '{cmd}'") # Log full traceback
        # Re-raise to be caught by the tool function
        raise RuntimeError(f"Failed executing command '{cmd}': {e}") from e


def initialize_msf_client():
    """Initializes the global Metasploit RPC client instance."""
    global _msf_client_instance
    if _msf_client_instance is not None:
        return _msf_client_instance

    logger.info("Attempting to initialize Metasploit RPC client...")

    # Use default values if environment variables are not set
    msf_password = os.environ.get('MSF_PASSWORD', 'yourpassword') # Default password
    msf_server = os.getenv('MSF_SERVER', '127.0.0.1')
    msf_port_str = os.getenv('MSF_PORT', '55553')

    try:
        msf_port = int(msf_port_str)
        client = MsfRpcClient(
            password=msf_password,
            server=msf_server,
            port=msf_port,
            ssl=os.getenv('MSF_SSL', 'false').lower() == 'true' # Optional SSL support
        )
        # Test connection during initialization
        version_info = client.core.version # Access as property, not as a method
        logger.info(f"Successfully connected to Metasploit RPC at {msf_server}:{msf_port}, version: {version_info.get('version', 'unknown')}")
        _msf_client_instance = client
        return _msf_client_instance
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid MSF_PORT: {msf_port_str}. Error: {e}")
        raise ValueError(f"Invalid MSF_PORT: {msf_port_str}") from e
    except MsfRpcError as e:
        logger.error(f"Failed to connect or authenticate to Metasploit RPC: {e}")
        raise ConnectionError(f"Failed to connect/authenticate to Metasploit RPC: {e}") from e
    except Exception as e:
        logger.error(f"An unexpected error occurred during MSF client initialization: {e}")
        raise RuntimeError(f"Unexpected error initializing MSF client: {e}") from e

# --- REVISED get_msf_console Function ---
@contextlib.asynccontextmanager
async def get_msf_console() -> Any:
    """Async context manager for creating and destroying an MSF console."""
    global _msf_client_instance
    console_object = None
    console_id_str = None # Store ID as string for consistency
    try:
        logger.debug("Attempting to create temporary console via client.consoles.console()")

        # --- Create console object (expecting the object itself) ---
        console_object = await asyncio.to_thread(lambda: _msf_client_instance.consoles.console())
        logger.debug(f"Console creation returned type: {type(console_object)}, value: {console_object}")

        # --- Get ID directly using .cid attribute (per README example) ---
        # Ensure it's the right type and has the attribute
        if isinstance(console_object, MsfConsole) and hasattr(console_object, 'cid'):
            try:
                # Access .cid and ensure it's a non-empty string
                console_id_val = getattr(console_object, 'cid')
                console_id_str = str(console_id_val) if console_id_val is not None else None

                if not console_id_str: # Check if empty or None after conversion
                    raise ValueError(".cid attribute is present but empty or None.")
                logger.info(f"Successfully obtained console object and extracted ID: {console_id_str}")
                # Yield the object we already have
                yield console_object

            except Exception as e:
                logger.error(f"Error accessing/validating .cid attribute on returned object: {e}")
                # Raise specific error if ID extraction from the expected object fails
                raise MsfRpcError(f"Got MsfConsole object, but failed to get valid ID from .cid: {console_object}") from e
        else:
            # If it didn't return the expected object with .cid
            logger.error(f"client.consoles.console() did not return expected MsfConsole object with .cid attribute. Got type: {type(console_object)}")
            raise MsfRpcError(f"Unexpected result from console creation: {console_object}")

    # --- Exception Handling ---
    except MsfRpcError as e:
        # Catch specific MsfRpcErrors (like the ones raised above)
        logger.error(f"MsfRpcError during console creation: {e}")
        # Re-raise with a clear message for the tool caller
        raise MsfRpcError(f"Error creating MSF console: {e}") from e # Propagate
    except Exception as e:
        # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error during console creation") # Log full traceback
        raise RuntimeError(f"Unexpected error during console creation: {e}") from e # Use standard error type
    finally:
        # --- Destruction Logic ---
        if console_id_str: # Use the string ID extracted via .cid
            try:
                logger.info(f"Attempting to destroy Metasploit console (ID: {console_id_str})...")
                destroy_result = await asyncio.to_thread(
                    lambda: _msf_client_instance.consoles.destroy(console_id_str)
                )
                # Log the result, which might be {'result': 'success'} or similar
                logger.debug(f"Console destroy result: {destroy_result}")
            except Exception as e:
                logger.error(f"Error destroying MSF console {console_id_str}: {e}")
        else:
            # If ID wasn't extracted, we can't reliably destroy
            logger.warning("No valid console ID was obtained via .cid, skipping destruction.")
# --- End of REVISED get_msf_console ---


# --- MCP Server Initialization ---
# Initialize MCP *before* defining tools
mcp = FastMCP("Metasploit Tools Improved")

# --- MCP Tool Definitions ---

@mcp.tool()
async def list_exploits(search_term: str = "") -> List[str]:
    """
    List available Metasploit exploits, optionally filtered by search term.

    Args:
        search_term: Optional term to filter exploits.

    Returns:
        List of exploit names matching the search term (max 100 if no term).
    """
    global _msf_client_instance
    logger.info(f"Listing exploits (search term: '{search_term or 'None'}')")
    try:
        exploits = await asyncio.to_thread(lambda: _msf_client_instance.modules.exploits)
        logger.debug(f"Retrieved {len(exploits)} total exploits from MSF.")
        if search_term:
            filtered_exploits = [e for e in exploits if search_term.lower() in e.lower()]
            logger.info(f"Found {len(filtered_exploits)} exploits matching '{search_term}'.")
            return filtered_exploits[:200]
        else:
            logger.info("No search term provided, returning first 100 exploits.")
            return exploits[:100]
    except MsfRpcError as e:
        logger.error(f"Failed to list exploits from Metasploit: {e}")
        return [f"Error listing exploits: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing exploits.")
        return [f"Unexpected error listing exploits: {e}"]

@mcp.tool()
async def list_payloads(platform: str = "", arch: str = "") -> List[str]:
    """
    List available Metasploit payloads, optionally filtered by platform/architecture.

    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux').
        arch: Optional architecture filter (e.g., 'x86', 'x64').

    Returns:
        List of payload names matching filters (max 100).
    """
    global _msf_client_instance
    logger.info(f"Listing payloads (platform: '{platform or 'Any'}', arch: '{arch or 'Any'}')")
    try:
        payloads = await asyncio.to_thread(lambda: _msf_client_instance.modules.payloads)
        logger.debug(f"Retrieved {len(payloads)} total payloads from MSF.")
        filtered = payloads
        if platform:
            filtered = [p for p in filtered if platform.lower() in p.lower()]
        if arch:
            filtered = [p for p in filtered if arch.lower() in p.lower()]
        count = len(filtered)
        limit = 100
        logger.info(f"Found {count} payloads matching filters. Returning max {limit}.")
        return filtered[:limit]
    except MsfRpcError as e:
        logger.error(f"Failed to list payloads from Metasploit: {e}")
        return [f"Error listing payloads: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing payloads.")
        return [f"Unexpected error listing payloads: {e}"]

@mcp.tool()
async def generate_payload_via_msfvenom(
    payload_type: str,
    lhost: str,
    lport: int,
    format_type: str = "raw",
) -> Dict[str, Any]:
    """
    Generate a Metasploit payload using the msfvenom command-line tool.
    Note: This requires msfvenom to be in the system's PATH where this script runs.

    Args:
        payload_type: Type of payload (e.g., windows/meterpreter/reverse_tcp).
        lhost: Listener host IP address.
        lport: Listener port.
        format_type: Output format (raw, exe, python, etc.).

    Returns:
        Dictionary containing status, message, and potentially truncated output/error.
    """
    logger.info(f"Generating payload '{payload_type}' for LHOST={lhost}, LPORT={lport}, Format={format_type}")
    cmd = [
        "msfvenom", "-p", payload_type, f"LHOST={lhost}", f"LPORT={str(lport)}", "-f", format_type,
    ]
    logger.debug(f"Executing command: {' '.join(shlex.quote(arg) for arg in cmd)}")
    try:
        process = await asyncio.to_thread(
            subprocess.run, cmd, check=True, capture_output=True, text=True, timeout=120
        )
        output_preview = process.stdout[:500] + ('...' if len(process.stdout) > 500 else '')
        logger.info(f"msfvenom succeeded for payload '{payload_type}'.")
        return {"status": "success", "message": f"Payload '{payload_type}' generated successfully.", "output_preview": output_preview}
    except subprocess.CalledProcessError as e:
        error_preview = e.stderr[:500] + ('...' if len(e.stderr) > 500 else '')
        logger.error(f"msfvenom failed for payload '{payload_type}'. Error: {e.stderr}")
        return {"status": "error", "message": f"Error generating payload '{payload_type}'. Exit code: {e.returncode}", "error_details": error_preview}
    except FileNotFoundError:
        logger.error("msfvenom command not found. Ensure Metasploit is installed and in PATH.")
        return {"status": "error", "message": "msfvenom command not found.", "error_details": "Ensure Metasploit Framework is installed and msfvenom is in the system PATH."}
    except subprocess.TimeoutExpired:
        logger.error(f"msfvenom command timed out for payload '{payload_type}'.")
        return {"status": "error", "message": f"Payload generation timed out for '{payload_type}'.", "error_details": "The msfvenom command took too long to execute."}
    except Exception as e:
        logger.exception(f"Unexpected error during payload generation for '{payload_type}'.")
        return {"status": "error", "message": "An unexpected error occurred during payload generation.", "error_details": str(e)}

# --- REWRITTEN MODULE EXECUTION FUNCTIONS ---

@mcp.tool()
async def run_exploit(
    module_name: str,
    options: Dict[str, Any], # Allow Any type for options initially
    payload: Optional[str] = None,
    payload_options: Optional[Dict[str, Any]] = None, # Allow Any type
    run_as_job: bool = False, # Default changed to False for more direct results
    timeout_seconds: int = 300 # Used for synchronous console execution
) -> Dict[str, Any]:
    """
    Run a Metasploit exploit module with specified options.
    Handles both synchronous (run_as_job=False) and asynchronous (run_as_job=True) execution.

    Args:
        module_name: Name of the exploit module (e.g., 'windows/smb/ms17_010_eternalblue').
        options: Dictionary of module options (e.g., {'RHOSTS': '192.168.1.1'}). Types matter (int, bool, str).
        payload: Payload to use (e.g., 'windows/meterpreter/reverse_tcp').
        payload_options: Dictionary of payload options (e.g., {'LHOST': '192.168.1.100', 'LPORT': 4444}). Types matter.
        run_as_job: If True, run as background job and return job info.
                    If False, run synchronously and return module output.
        timeout_seconds: Max time for synchronous run via console.

    Returns:
        Dictionary with execution results (job info or module output) or error details.
    """
    global _msf_client_instance
    logger.info(f"Running exploit {module_name}. Run as job: {run_as_job}. Options: {options}, Payload: {payload}, Payload Opts: {payload_options}")

    # --- Input Validation ---
    if '/' not in module_name:
        module_name = f"exploit/{module_name}"
    elif not module_name.startswith('exploit/'):
        logger.error(f"Invalid exploit module name provided: {module_name}")
        return {"status": "error", "message": f"Invalid exploit module name: {module_name}. Should start with 'exploit/' or be just the name."}

    module_options = options or {}
    final_payload_options = payload_options or {}

    try:
        if run_as_job:
            # --- Asynchronous Execution (Run as Job) ---
            logger.info(f"Executing {module_name} as background job.")
            # Get the exploit module object
            base_module_name = module_name.replace('exploit/', '', 1)
            module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('exploit', base_module_name))
            logger.debug(f"Retrieved exploit module object for '{base_module_name}'")

            # Set exploit options with type conversion
            for k, v in module_options.items():
                if isinstance(v, str):
                    if v.isdigit(): v = int(v)
                    elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
                await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))

            # Set payload if provided
            if payload:
                await asyncio.to_thread(lambda: module_obj.__setitem__('PAYLOAD', payload))
                # Set payload options with type conversion
                for k, v in final_payload_options.items():
                    if isinstance(v, str):
                        if v.isdigit(): v = int(v)
                        elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
                    await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))

            # Execute the module (likely runs as job by default)
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())
            logger.info(f"module_obj.execute() result: {exec_result}")

            # Process job result
            if isinstance(exec_result, dict):
                job_id = exec_result.get('job_id')
                uuid = exec_result.get('uuid')
                if 'error' in exec_result and exec_result['error']:
                     error_message = f"Failed to start exploit module job: {exec_result.get('error_message', exec_result.get('error_string', 'Unknown error'))}"
                     logger.error(error_message)
                     return {"status": "error", "message": error_message, "module": module_name}
                elif job_id is not None:
                    message = f"Exploit module {module_name} started as job {job_id}."
                    # Check for associated session quickly
                    await asyncio.sleep(1.5)
                    sessions_list = await asyncio.to_thread(lambda: _msf_client_instance.sessions.list)
                    found_session_id = None
                    for s_id, s_info in sessions_list.items():
                        if isinstance(s_info, dict) and s_info.get('exploit_uuid') == uuid:
                            found_session_id = s_id
                            message += f" Session {found_session_id} created."
                            logger.info(f"Found session {found_session_id} matching exploit UUID {uuid}")
                            break
                    return {
                        "status": "success", "message": message, "job_id": job_id, "uuid": uuid,
                        "session_id": found_session_id, "module": module_name, "options": options,
                        "payload": payload, "payload_options": payload_options
                    }
                else:
                     logger.warning(f"Exploit job execution result did not contain job_id: {exec_result}")
                     return {"status": "unknown", "message": f"Exploit module {module_name} execution finished, but no job ID was returned.", "result": exec_result, "module": module_name}
            else:
                logger.error(f"Unexpected result format from exploit module execute: {exec_result}")
                return {"status": "error", "message": f"Unexpected result format from exploit execution: {exec_result}", "module": module_name}

        else:
            # --- Synchronous Execution (via Console) ---
            logger.info(f"Executing {module_name} synchronously via console.")
            async with get_msf_console() as console:
                setup_commands = [f"use {module_name}"]
                # Add exploit options
                for key, value in module_options.items():
                    # Quote value if it's a string containing spaces or special chars?
                    # shlex.quote might be too aggressive here, basic check:
                    val_str = str(value)
                    if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                         val_str = shlex.quote(val_str) # Use shlex for safety
                    setup_commands.append(f"set {key} {val_str}")

                # Add payload and options
                if payload:
                    setup_commands.append(f"set PAYLOAD {payload}")
                    for key, value in final_payload_options.items():
                        val_str = str(value)
                        if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                             val_str = shlex.quote(val_str)
                        setup_commands.append(f"set {key} {val_str}")

                final_command = "exploit" # Synchronous command

                # Execute setup commands
                for cmd in setup_commands:
                    logger.debug(f"Running setup command: {cmd}")
                    setup_output = await run_command_safely(console, cmd, execution_timeout=15) # Short timeout for setup
                    if "[-] Error" in setup_output or "fail" in setup_output.lower():
                        error_msg = f"Error during setup command '{cmd}': {setup_output}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg}
                    await asyncio.sleep(0.1) # Small delay

                # Execute the final command
                logger.info(f"Running final command: {final_command}")
                module_output = await run_command_safely(console, final_command, execution_timeout=timeout_seconds)
                logger.debug(f"Synchronous execution output length: {len(module_output)}")

                # Try to parse session ID from output (best effort)
                session_id = None
                for line in module_output.splitlines():
                     if "session" in line.lower() and "opened" in line.lower():
                         try:
                             parts = line.split()
                             for i, part in enumerate(parts):
                                 if part.lower() == "session" and i + 1 < len(parts) and parts[i + 1].isdigit():
                                     session_id = int(parts[i + 1])
                                     logger.info(f"Detected session {session_id} opened in output.")
                                     break
                             if session_id: break # Stop after finding first session
                         except (ValueError, IndexError):
                             pass # Ignore parsing errors

                return {
                    "status": "success",
                    "message": f"Exploit module {module_name} completed synchronously.",
                    "module_output": module_output,
                    "session_id_detected": session_id, # Note if a session was seen in output
                    "module": module_name,
                    "options": options,
                    "payload": payload,
                    "payload_options": payload_options
                }

    except MsfRpcError as e:
        if "Unknown module" in str(e) or "failed to load" in str(e).lower():
            logger.error(f"Exploit module {module_name} not found or failed to load: {e}")
            return {"status": "error", "message": f"Exploit module {module_name} not found or failed to load."}
        logger.error(f"MsfRpcError running exploit {module_name}: {e}")
        return {"status": "error", "message": f"Error running exploit: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error running exploit {module_name}")
        return {"status": "error", "message": f"Unexpected error running exploit: {str(e)}"}

@mcp.tool()
async def run_post_module(
    module_name: str,
    session_id: int,
    options: Dict[str, Any] = None, # Allow Any
    run_as_job: bool = True, # Keep True as default for post? Often less critical for immediate output
    timeout_seconds: int = 300
) -> Dict[str, Any]:
    """
    Run a Metasploit post-exploitation module against a session.
    Handles both synchronous (run_as_job=False) and asynchronous (run_as_job=True) execution.
    """
    global _msf_client_instance
    if '/' not in module_name: module_name = f"post/{module_name}"
    elif not module_name.startswith('post/'): logger.warning(f"Running non-post module '{module_name}' with run_post_module tool.")

    logger.info(f"Running post module {module_name} on session {session_id}. Run as job: {run_as_job}")
    module_options = options or {}
    module_options['SESSION'] = session_id # Ensure session is set

    try:
        if run_as_job:
            # --- Asynchronous Execution (Run as Job) ---
            logger.info(f"Executing {module_name} as background job.")
            base_module_name = module_name.replace('post/', '', 1)
            module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('post', base_module_name))
            logger.debug(f"Retrieved module object for '{base_module_name}'")

            # Set options with type conversion
            for k, v in module_options.items():
                 if isinstance(v, str):
                     if v.isdigit(): v = int(v)
                     elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
                 # Special case for SESSION ID
                 if k == 'SESSION': v = int(v)
                 await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))

            # Execute the module
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())
            logger.info(f"module_obj.execute() result: {exec_result}")

            if isinstance(exec_result, dict):
                 job_id = exec_result.get('job_id')
                 uuid = exec_result.get('uuid')
                 if 'error' in exec_result and exec_result['error']:
                      error_message = f"Failed to execute post module job: {exec_result.get('error_message', 'Unknown error')}"
                      logger.error(error_message)
                      return {"status": "error", "message": error_message, "module": module_name, "session_id": session_id}
                 elif job_id is not None:
                      return {"status": "success", "message": f"Post module {module_name} started as job {job_id}", "job_id": job_id, "uuid": uuid, "module": module_name, "session_id": session_id}
                 else:
                     logger.warning(f"Post module job execution result format unknown: {exec_result}")
                     return {"status": "unknown", "message": "Post module execution finished, but job ID missing.", "result": exec_result, "module": module_name, "session_id": session_id}
            else:
                 logger.error(f"Unexpected result format from post module execute: {exec_result}")
                 return {"status": "error", "message": f"Unexpected result format from post execution: {exec_result}", "module": module_name}

        else:
            # --- Synchronous Execution (via Console) ---
            logger.info(f"Executing {module_name} synchronously via console.")
            async with get_msf_console() as console:
                setup_commands = [f"use {module_name}"]
                # Add options
                for key, value in module_options.items():
                    val_str = str(value)
                    # Quote value if it's a string containing spaces or special chars?
                    if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                         val_str = shlex.quote(val_str)
                    setup_commands.append(f"set {key} {val_str}")

                final_command = "run" # Synchronous command

                # Execute setup commands
                for cmd in setup_commands:
                    logger.debug(f"Running setup command: {cmd}")
                    setup_output = await run_command_safely(console, cmd, execution_timeout=15) # Short timeout for setup
                    if "[-] Error" in setup_output or "fail" in setup_output.lower():
                        error_msg = f"Error during setup command '{cmd}': {setup_output}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg}
                    await asyncio.sleep(0.1) # Small delay

                # Execute the final command
                logger.info(f"Running final command: {final_command}")
                module_output = await run_command_safely(console, final_command, execution_timeout=timeout_seconds)
                logger.debug(f"Synchronous execution output length: {len(module_output)}")

                return {
                    "status": "success",
                    "message": f"Post module {module_name} completed synchronously.",
                    "module_output": module_output,
                    "module": module_name,
                    "session_id": session_id,
                    "options": options # Return original options
                }

    except MsfRpcError as e:
        if "Unknown module" in str(e): return {"status": "error", "message": f"Post module {module_name} not found."}
        if "Invalid Session" in str(e): return {"status": "error", "message": f"Invalid Session ID: {session_id} for module {module_name}."}
        logger.error(f"MsfRpcError running post module {module_name}: {e}")
        return {"status": "error", "message": f"Error running post module: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error running post module {module_name}")
        return {"status": "error", "message": f"Unexpected error running post module: {str(e)}"}


@mcp.tool()
async def run_auxiliary_module(
    module_name: str,
    options: Dict[str, Any], # Allow Any
    run_as_job: bool = False, # Default changed to False for scanners
    timeout_seconds: int = 300
) -> Dict[str, Any]:
    """
    Run a Metasploit auxiliary module.
    Handles both synchronous (run_as_job=False) and asynchronous (run_as_job=True) execution.
    """
    global _msf_client_instance
    if '/' not in module_name: module_name = f"auxiliary/{module_name}"
    elif not module_name.startswith('auxiliary/'): return {"status": "error", "message": f"Invalid auxiliary module name: {module_name}."}

    logger.info(f"Running auxiliary module {module_name}. Run as job: {run_as_job}. Options: {options}")
    module_options = options or {}

    try:
        if run_as_job:
             # --- Asynchronous Execution (Run as Job) ---
            logger.info(f"Executing {module_name} as background job.")
            base_module_name = module_name.replace('auxiliary/', '', 1)
            module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('auxiliary', base_module_name))
            logger.debug(f"Retrieved module object for '{base_module_name}'")

            # Set options with type conversion
            for k, v in module_options.items():
                 if isinstance(v, str):
                     if v.isdigit(): v = int(v)
                     elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
                 await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))

            # Execute the module
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())
            logger.info(f"module_obj.execute() result: {exec_result}")

            if isinstance(exec_result, dict):
                 job_id = exec_result.get('job_id')
                 uuid = exec_result.get('uuid')
                 if 'error' in exec_result and exec_result['error']:
                      error_message = f"Failed to execute auxiliary module job: {exec_result.get('error_message', 'Unknown error')}"
                      logger.error(error_message)
                      return {"status": "error", "message": error_message, "module": module_name, "options": options}
                 elif job_id is not None:
                      return {"status": "success", "message": f"Auxiliary module {module_name} started as job {job_id}", "job_id": job_id, "uuid": uuid, "module": module_name, "options": options}
                 else:
                      # Attempt UUID matching if no job_id returned directly
                      if uuid:
                           await asyncio.sleep(1.0) # Give job time to potentially register
                           jobs = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
                           for jid, jinfo in jobs.items():
                                if isinstance(jinfo, dict) and jinfo.get('uuid') == uuid:
                                     logger.info(f"Found matching job {jid} for uuid {uuid}")
                                     return {"status": "success", "message": f"Auxiliary module {module_name} likely started as job {jid} (matched UUID)", "job_id": jid, "uuid": uuid, "module": module_name, "options": options}
                      # If no UUID match or no UUID, return unknown
                      logger.warning(f"Auxiliary module job execution result format unknown/job ID missing: {exec_result}")
                      return {"status": "unknown", "message": "Auxiliary module execution finished, but result format unknown/job ID missing.", "result": exec_result, "module": module_name, "options": options}
            else:
                 logger.error(f"Unexpected result format from auxiliary module execute: {exec_result}")
                 return {"status": "error", "message": f"Unexpected result format from auxiliary execution: {exec_result}", "module": module_name}

        else:
            # --- Synchronous Execution (via Console) ---
            logger.info(f"Executing {module_name} synchronously via console.")
            async with get_msf_console() as console:
                setup_commands = [f"use {module_name}"]
                # Add options
                for key, value in module_options.items():
                    val_str = str(value)
                    # Quote value if it's a string containing spaces or special chars?
                    if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                         val_str = shlex.quote(val_str)
                    setup_commands.append(f"set {key} {val_str}")

                final_command = "run" # Synchronous command

                # Execute setup commands
                for cmd in setup_commands:
                    logger.debug(f"Running setup command: {cmd}")
                    setup_output = await run_command_safely(console, cmd, execution_timeout=15) # Short timeout for setup
                    if "[-] Error" in setup_output or "fail" in setup_output.lower():
                        error_msg = f"Error during setup command '{cmd}': {setup_output}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg}
                    await asyncio.sleep(0.1) # Small delay

                # Execute the final command
                logger.info(f"Running final command: {final_command}")
                module_output = await run_command_safely(console, final_command, execution_timeout=timeout_seconds)
                logger.debug(f"Synchronous execution output length: {len(module_output)}")

                return {
                    "status": "success",
                    "message": f"Auxiliary module {module_name} completed synchronously.",
                    "module_output": module_output,
                    "module": module_name,
                    "options": options # Return original options
                }

    except MsfRpcError as e:
        if "Unknown module" in str(e): return {"status": "error", "message": f"Auxiliary module {module_name} not found."}
        logger.error(f"MsfRpcError running auxiliary module {module_name}: {e}")
        return {"status": "error", "message": f"Error running auxiliary module: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error running auxiliary module {module_name}")
        return {"status": "error", "message": f"Unexpected error running auxiliary module: {str(e)}"}


# --- Tools relying on send_session_command (Unchanged) ---
@mcp.tool()
async def list_active_sessions() -> Dict[str, Any]:
    """
    List active Metasploit sessions.

    Returns:
        Dictionary of active sessions or an error message.
    """
    global _msf_client_instance
    logger.info("Listing active Metasploit sessions.")
    try:
        sessions_dict = await asyncio.to_thread(lambda: _msf_client_instance.sessions.list)
        if not isinstance(sessions_dict, dict):
            logger.error(f"Expected dict from sessions.list, got {type(sessions_dict)}")
            return {"status": "error", "message": f"Unexpected data type received for sessions list: {type(sessions_dict)}"}
        logger.info(f"Found {len(sessions_dict)} active sessions.")
        return {"status": "success", "sessions": sessions_dict}
    except MsfRpcError as e:
        logger.error(f"Failed to list sessions: {e}")
        return {"status": "error", "message": f"Error listing sessions: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error listing sessions.")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

@mcp.tool()
async def send_session_command(
    session_id: int,
    command: str,
    timeout_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Send a command to an active Metasploit session and get output.

    Args:
        session_id: ID of the target session.
        command: Command string to execute in the session.
        timeout_seconds: Maximum time to wait for the command to complete.

    Returns:
        Dictionary with status and command output or error details.
    """
    global _msf_client_instance
    logger.info(f"Sending command to session {session_id}: '{command}'")
    try:
        session_id_str = str(session_id)
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))
        if not session:
            logger.error(f"Session {session_id} not found.")
            return {"status": "error", "message": f"Session {session_id} not found."}

        # Use session.write and session.read for more control
        logger.debug(f"Writing command to session {session_id}: {command}")
        await asyncio.to_thread(session.write, command + '\n')

        # Read output with timeout
        output_buffer = ""
        start_time = asyncio.get_event_loop().time()
        read_interval = 0.2 # Check frequently
        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            await asyncio.sleep(read_interval)
            read_data = await asyncio.to_thread(session.read)
            if read_data:
                output_buffer += read_data
                # Add a small extra delay if we just read data, maybe more is coming
                await asyncio.sleep(0.3)
            # Heuristic break check (optional, might be fragile)
            # elif any(output_buffer.strip().endswith(p) for p in ["meterpreter >", ">", "#", "$"]):
            #     logger.debug("Detected potential prompt, finishing read early.")
            #     break

        if not output_buffer and (asyncio.get_event_loop().time() - start_time) >= timeout_seconds:
            logger.warning(f"Command '{command}' execution timed out after {timeout_seconds}s on session {session_id}. No output received.")
            return {"status": "timeout", "message": f"Command execution timed out after {timeout_seconds} seconds. No output.", "output": ""}

        elif output_buffer and (asyncio.get_event_loop().time() - start_time) >= timeout_seconds:
            logger.warning(f"Command '{command}' execution potentially timed out after {timeout_seconds}s on session {session_id}. Returning partial output.")
            status = "timeout"
            message = f"Command execution potentially timed out after {timeout_seconds} seconds. Returning collected output."
        else:
            logger.info(f"Command executed successfully on session {session_id}.")
            status = "success"
            message = "Command executed."

        # Limit output size
        output_preview = output_buffer[:2000] + ('...' if len(output_buffer) > 2000 else '')
        return {"status": status, "message": message, "output": output_preview}

    except MsfRpcError as e:
        logger.error(f"MsfRpcError sending command to session {session_id}: {e}")
        return {"status": "error", "message": f"Error interacting with session {session_id}: {str(e)}"}
    except KeyError: # Often indicates session ID not found in pymetasploit3 dict
        logger.error(f"Session {session_id} likely not found (KeyError).")
        return {"status": "error", "message": f"Session {session_id} not found."}
    except Exception as e:
        logger.exception(f"Unexpected error sending command to session {session_id}.")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

@mcp.tool()
async def get_system_info(session_id: int) -> Dict[str, Any]:
    """
    Get system information from a Meterpreter session using send_session_command.
    Args:
        session_id: ID of the Meterpreter session.
    Returns:
        Dictionary with system information or error details.
    """
    logger.info(f"Getting system info for session {session_id} via send_session_command")
    # First verify it's likely a meterpreter session to avoid running 'sysinfo' on a shell
    try:
        session_id_str = str(session_id)
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))
        if not session: return {"status": "error", "message": f"Session {session_id} not found."}
        session_info = await asyncio.to_thread(lambda: session.info)
        session_type = session_info.get('type') if isinstance(session_info, dict) else None
        if session_type != 'meterpreter':
            return {"status": "error", "message": f"Session {session_id} is not Meterpreter (type: {session_type}). sysinfo requires Meterpreter."}
    except Exception as e:
        logger.error(f"Error checking session type for {session_id}: {e}")
        return {"status": "error", "message": f"Could not verify session type for {session_id}: {e}"}

    # Run sysinfo command
    sysinfo_result = await send_session_command(session_id, 'sysinfo', timeout_seconds=30)

    if sysinfo_result.get("status") in ["success", "timeout"]: # Treat timeout as partial success here
        raw_output = sysinfo_result.get("output", "")
        logger.info(f"Received sysinfo output (Status: {sysinfo_result.get('status')}). Parsing...")
        parsed_info = {}
        for line in raw_output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                parsed_info[key.strip()] = value.strip()

        # Return even if parsing is incomplete on timeout
        return {"status": "success", "sysinfo": parsed_info, "raw_output": raw_output, "command_status": sysinfo_result.get("status")}
    else:
        logger.error(f"Failed to run 'sysinfo' via send_session_command: {sysinfo_result.get('message')}")
        return sysinfo_result # Propagate error

@mcp.tool()
async def get_user_id(session_id: int) -> Dict[str, Any]:
    """
    Get the current user ID from a Meterpreter session using send_session_command.
    Args:
        session_id: ID of the Meterpreter session.
    Returns:
        Dictionary with user information or error details.
    """
    logger.info(f"Getting user ID for session {session_id} via send_session_command")
    # First verify it's likely a meterpreter session
    try:
        session_id_str = str(session_id)
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))
        if not session: return {"status": "error", "message": f"Session {session_id} not found."}
        session_info = await asyncio.to_thread(lambda: session.info)
        session_type = session_info.get('type') if isinstance(session_info, dict) else None
        if session_type != 'meterpreter':
            return {"status": "error", "message": f"Session {session_id} is not Meterpreter (type: {session_type}). getuid requires Meterpreter."}
    except Exception as e:
        logger.error(f"Error checking session type for {session_id}: {e}")
        return {"status": "error", "message": f"Could not verify session type for {session_id}: {e}"}

    # Run getuid command
    getuid_result = await send_session_command(session_id, 'getuid', timeout_seconds=30)

    if getuid_result.get("status") in ["success", "timeout"]:
        raw_output = getuid_result.get("output", "")
        logger.info(f"Received getuid output (Status: {getuid_result.get('status')}): {raw_output.strip()}")
        username = raw_output.strip()
        if ":" in username: # Handle "Server username: ..." format
            username = username.split(":", 1)[1].strip()
        return {"status": "success", "username": username, "raw_output": raw_output, "command_status": getuid_result.get("status")}
    else:
        logger.error(f"Failed to run 'getuid' via send_session_command: {getuid_result.get('message')}")
        return getuid_result # Propagate error

@mcp.tool()
async def list_processes(session_id: int) -> Dict[str, Any]:
    """
    List running processes via a Meterpreter session using send_session_command.
    Args:
        session_id: ID of the Meterpreter session.
    Returns:
        Dictionary with process list or error details.
    """
    logger.info(f"Listing processes for session {session_id} via send_session_command")
      # First verify it's likely a meterpreter session
    try:
        session_id_str = str(session_id)
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))
        if not session: return {"status": "error", "message": f"Session {session_id} not found."}
        session_info = await asyncio.to_thread(lambda: session.info)
        session_type = session_info.get('type') if isinstance(session_info, dict) else None
        if session_type != 'meterpreter':
            return {"status": "error", "message": f"Session {session_id} is not Meterpreter (type: {session_type}). 'ps' command requires Meterpreter."}
    except Exception as e:
        logger.error(f"Error checking session type for {session_id}: {e}")
        return {"status": "error", "message": f"Could not verify session type for {session_id}: {e}"}

    # Run ps command
    ps_result = await send_session_command(session_id, 'ps', timeout_seconds=45)

    if ps_result.get("status") in ["success", "timeout"]:
        raw_output = ps_result.get("output", "")
        logger.info(f"Received ps output (Status: {ps_result.get('status')}). Parsing...")
        lines = raw_output.strip().splitlines()
        processes = []
        header_found = False
        # Improved parsing logic
        pid_col, ppid_col, name_col, arch_col, user_col, session_col, path_col = -1, -1, -1, -1, -1, -1, -1
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line: continue

            if "PID" in line and "Name" in line: # Find header row
                header_found = True
                # Attempt to find column start indices (approximate)
                pid_col = line.find("PID")
                ppid_col = line.find("PPID")
                name_col = line.find("Name")
                arch_col = line.find("Arch")
                user_col = line.find("User")
                session_col = line.find("Session")
                path_col = line.find("Path")
                # If exact match fails, use rough estimates based on PID/PPID/Name
                if ppid_col < pid_col: ppid_col = pid_col + 4
                if name_col < ppid_col: name_col = ppid_col + 6
                if arch_col < name_col: arch_col = -1 # Might not exist
                if user_col < (arch_col if arch_col != -1 else name_col): user_col = (arch_col if arch_col != -1 else name_col) + 6
                if session_col < user_col: session_col = -1 # Might not exist
                if path_col < (session_col if session_col != -1 else user_col) : path_col = (session_col if session_col != -1 else user_col) + 15
                continue # Skip header line itself

            if not header_found: continue # Skip lines until header is found

            # Extract data based on rough column positions if possible
            # This is still heuristic and might fail on weird formatting
            try:
                pid_str = line[:ppid_col].strip() if ppid_col > 0 else line.split()[0]
                if not pid_str.isdigit(): continue # Skip if first part isn't PID

                proc_info = {"pid": int(pid_str)}
                if ppid_col > 0 and name_col > ppid_col:
                    ppid_str = line[ppid_col:name_col].strip()
                    if ppid_str.isdigit(): proc_info["ppid"] = int(ppid_str)
                if name_col > 0:
                    end_name = arch_col if arch_col > name_col else (user_col if user_col > name_col else (session_col if session_col > name_col else (path_col if path_col > name_col else -1)))
                    proc_info["name"] = line[name_col:end_name].strip() if end_name > 0 else line[name_col:].split()[0] # Best guess
                # Add other fields similarly if columns were found
                # ... (parsing for arch, user, session, path is complex and error-prone) ...

                processes.append(proc_info)

            except Exception as parse_e:
                logger.warning(f"Could not parse process line using columns: '{line}'. Error: {parse_e}")
                # Fallback to simple split? Might be worse.
                # parts = stripped_line.split(None, 4)
                # if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit(): # Basic check
                #     processes.append({"pid": parts[0], "ppid": parts[1], "name": parts[2], "user": parts[3], "path": parts[4] if len(parts)>4 else ""})

        status_msg = f"Processed 'ps' output (Status: {ps_result.get('status')}). Found {len(processes)} processes."
        if not header_found and raw_output:
            status_msg = "Retrieved process list but couldn't parse structured data (header not found)."
            return {"status": "partial_success", "message": status_msg, "raw_output": raw_output}

        return {"status": "success", "message": status_msg, "processes": processes, "process_count": len(processes), "raw_output": raw_output}

    else:
        logger.error(f"Failed to run 'ps' via send_session_command: {ps_result.get('message')}")
        return ps_result # Propagate error

@mcp.tool()
async def migrate_process(session_id: int, pid: int) -> Dict[str, Any]:
    """
    Migrate the Meterpreter session to another process using send_session_command.
    Args:
        session_id: ID of the Meterpreter session.
        pid: Process ID to migrate to.
    Returns:
        Dictionary with migration status or error details.
    """
    logger.info(f"Attempting to migrate session {session_id} to process {pid} via send_session_command")
      # First verify it's likely a meterpreter session
    try:
        session_id_str = str(session_id)
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))
        if not session: return {"status": "error", "message": f"Session {session_id} not found."}
        session_info = await asyncio.to_thread(lambda: session.info)
        session_type = session_info.get('type') if isinstance(session_info, dict) else None
        if session_type != 'meterpreter':
            return {"status": "error", "message": f"Session {session_id} is not Meterpreter (type: {session_type}). Migration requires Meterpreter."}
    except Exception as e:
        logger.error(f"Error checking session type for {session_id}: {e}")
        return {"status": "error", "message": f"Could not verify session type for {session_id}: {e}"}

    # Run migrate command
    migrate_command = f"migrate {pid}"
    migrate_result = await send_session_command(session_id, migrate_command, timeout_seconds=60)

    # Check status from send_session_command first
    if migrate_result.get("status") not in ["success", "timeout"]:
        logger.error(f"Failed to run 'migrate' command via send_session_command: {migrate_result.get('message')}")
        return migrate_result # Propagate underlying error

    raw_output = migrate_result.get("output", "")
    logger.info(f"Migration command finished (Status: {migrate_result.get('status')}). Raw output:\n{raw_output}")

    # Check for common success/failure indicators
    success = "migration completed successfully" in raw_output.lower() or "successfully migrated" in raw_output.lower()
    failure = "migration failed" in raw_output.lower() or "[-] error" in raw_output.lower() or "operation failed" in raw_output.lower()

    final_status = "success" if success else "error" if failure else "unknown"
    message = "Migration completed successfully." if success else "Migration failed." if failure else "Migration status unknown (check raw output)."

    if migrate_result.get("status") == "timeout":
        final_status = "unknown" # Override status if command timed out
        message = f"Migration command timed out after 60 seconds. Status unknown. Check raw output."

    return {"status": final_status, "message": message, "target_pid": pid, "raw_output": raw_output}


@mcp.tool()
async def filesystem_list(session_id: int, remote_path: str) -> Dict[str, Any]:
    """
    List files in a directory via a Meterpreter session using send_session_command.
    Args:
        session_id: ID of the Meterpreter session.
        remote_path: Path to list on the remote system.
    Returns:
        Dictionary with file listing or error details.
    """
    logger.info(f"Listing files at '{remote_path}' for session {session_id} via send_session_command")
    # Basic input validation
    if not isinstance(remote_path, str) or any(c in remote_path for c in ';|&`$()<>'):
        logger.error(f"Invalid characters detected in remote path: {remote_path}")
        return {"status": "error", "message": "Invalid path provided."}
      # First verify it's likely a meterpreter session
    try:
        session_id_str = str(session_id)
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))
        if not session: return {"status": "error", "message": f"Session {session_id} not found."}
        session_info = await asyncio.to_thread(lambda: session.info)
        session_type = session_info.get('type') if isinstance(session_info, dict) else None
        if session_type != 'meterpreter':
            return {"status": "error", "message": f"Session {session_id} is not Meterpreter (type: {session_type}). Filesystem commands require Meterpreter."}
    except Exception as e:
        logger.error(f"Error checking session type for {session_id}: {e}")
        return {"status": "error", "message": f"Could not verify session type for {session_id}: {e}"}

    # Run ls command
    escaped_path = remote_path.replace("\"", "\\\"") # Move escaping outside f-string
    ls_command = f'ls "{escaped_path}"' # Use the escaped path in f-string
    ls_result = await send_session_command(session_id, ls_command, timeout_seconds=30)

    if ls_result.get("status") in ["success", "timeout"]:
        raw_output = ls_result.get("output", "")
        logger.info(f"Received ls output (Status: {ls_result.get('status')}). Parsing...")
        lines = raw_output.strip().splitlines()
        files = []
        header_found = False
        listing_path = remote_path # Default path
        message = f"Listing for '{remote_path}'"

        for line in lines:
            stripped = line.strip()
            if not stripped: continue
            if stripped.startswith("Listing:"):
                try: listing_path = stripped.split(":", 1)[1].strip()
                except: pass
                continue
            if "Mode" in stripped and "Size" in stripped and "Type" in stripped:
                header_found = True
                continue
            if not header_found: continue

            parts = stripped.split(None, 4)
            if len(parts) >= 5:
                try:
                    size_val = parts[1]; size_int = int(size_val) if size_val.isdigit() else size_val
                    files.append({"mode": parts[0], "size": size_int, "type": parts[2], "last_modified": parts[3], "name": parts[4]})
                except IndexError: logger.warning(f"Could not parse file line: {stripped}")
            else: logger.debug(f"Skipping potential non-file line: {stripped}")

        # Determine final status message
        if not files and "0 directories, 0 files" in raw_output: message = f"Directory '{listing_path}' is empty."
        elif not files and ("[-] stdapi_fs_ls: Operation failed: The system cannot find the file specified." in raw_output or "No such file or directory" in raw_output):
            return {"status": "error", "message": f"Path '{remote_path}' not found or error during listing.", "raw_output": raw_output}
        elif not files and header_found: message = f"Directory '{listing_path}' listed, but no files parsed."
        elif not files and not header_found:
            message = f"Command executed for '{listing_path}', but could not parse output. Check raw output."
            return {"status": "partial_success", "message": message, "path": listing_path, "raw_output": raw_output}
        elif files: message = f"Successfully listed {len(files)} files/dirs in '{listing_path}'."

        return {"status": "success", "path": listing_path, "files": files, "file_count": len(files), "message": message, "raw_output": raw_output}
    else: # Handle errors from send_session_command itself
        logger.error(f"Failed to run 'ls' via send_session_command: {ls_result.get('message')}")
        raw_output = ls_result.get("output", "") # Check output even on error
        if "[-] stdapi_fs_ls: Operation failed: The system cannot find the file specified." in raw_output or "No such file or directory" in raw_output:
            return {"status": "error", "message": f"Path '{remote_path}' not found or error during listing.", "raw_output": raw_output}
        return ls_result # Propagate other errors

@mcp.tool()
async def list_listeners() -> Dict[str, Any]:
    """
    List all active job handlers (listeners) in Metasploit.
    """
    global _msf_client_instance
    logger.info("Listing active listeners/jobs")
    try:
        jobs = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
        if not isinstance(jobs, dict):
            return {"status": "error", "message": f"Unexpected data type for jobs list: {type(jobs)}"}
        logger.info(f"Found {len(jobs)} active jobs")
        handlers = {}; other_jobs = {}
        for job_id, job_info in jobs.items():
            if not isinstance(job_info, dict): continue
            job_name = job_info.get('name', '')
            if 'exploit/multi/handler' in job_name:
                datastore = job_info.get('datastore', {})
                if not isinstance(datastore, dict): datastore = {}
                handlers[job_id] = {'job_id': job_id, 'start_time': job_info.get('start_time'), 'name': job_name, 'payload': datastore.get('PAYLOAD', 'unknown'), 'lhost': datastore.get('LHOST', 'unknown'), 'lport': datastore.get('LPORT', 'unknown')}
            else: other_jobs[job_id] = {'job_id': job_id, 'start_time': job_info.get('start_time'), 'name': job_name}
        return {"status": "success", "handlers": handlers, "other_jobs": other_jobs, "handler_count": len(handlers), "other_job_count": len(other_jobs), "total_job_count": len(jobs)}
    except MsfRpcError as e:
        logger.error(f"Error listing jobs/handlers: {e}")
        return {"status": "error", "message": f"Error listing jobs: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error listing jobs/handlers.")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

@mcp.tool()
async def start_listener(
    payload_type: str,
    lhost: str,
    lport: int,
    additional_options: Optional[Dict[str, Any]] = None # Allow Any
) -> Dict[str, Any]:
    """
    Start a new Metasploit handler using module.use pattern. Always runs as a job.
    Args:
        payload_type: The payload to handle (e.g., 'windows/meterpreter/reverse_tcp').
        lhost: Listener host address.
        lport: Listener port.
        additional_options: Optional dictionary of additional handler options. Types matter.
    Returns:
        Dictionary with handler status or error details.
    """
    global _msf_client_instance
    logger.info(f"Starting listener for {payload_type} on {lhost}:{lport}")
    try:
        if not all([isinstance(payload_type, str), isinstance(lhost, str), isinstance(lport, int)]):
            return {"status": "error", "message": "Invalid input types."}
        if not (1 <= lport <= 65535):
            return {"status": "error", "message": "Invalid LPORT."}

        # Get the exploit/multi/handler module
        module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('exploit', 'multi/handler'))
        logger.debug(f"Retrieved handler module object")

        # Set options on the module
        await asyncio.to_thread(lambda: module_obj.__setitem__('PAYLOAD', payload_type))
        await asyncio.to_thread(lambda: module_obj.__setitem__('LHOST', lhost))
        await asyncio.to_thread(lambda: module_obj.__setitem__('LPORT', lport)) # Use integer directly
        await asyncio.to_thread(lambda: module_obj.__setitem__('ExitOnSession', False)) # Use boolean directly

        # Set any additional options with type conversion
        if additional_options:
            for k, v in additional_options.items():
                if isinstance(v, str):
                    if v.isdigit(): v = int(v)
                    elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
                await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))

        # Execute the module (will run as a job)
        exec_result = await asyncio.to_thread(lambda: module_obj.execute())
        logger.info(f"Handler module execution result: {exec_result}")

        if isinstance(exec_result, dict) and 'job_id' in exec_result:
            job_id = exec_result.get('job_id')
            await asyncio.sleep(0.5) # Give job time to appear
            jobs_list = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
            if str(job_id) in jobs_list:
                logger.info(f"Listener started successfully as job {job_id}.")
                return {"status": "success", "message": f"Listener started as job {job_id}", "job_id": job_id, "uuid": exec_result.get('uuid'), "payload": payload_type, "lhost": lhost, "lport": lport}
            else:
                logger.error(f"Module execution reported job ID {job_id}, but job not found.")
                return {"status": "error", "message": f"Listener job {job_id} reported but not found."}
        else:
            error_message = f"Failed to start listener. Result: {exec_result}"
            if isinstance(exec_result, dict) and 'error' in exec_result:
                error_message = f"Failed to start listener: {exec_result.get('error_message', exec_result.get('error_string', 'Unknown error'))}"
            logger.error(error_message)
            return {"status": "error", "message": error_message}
    except MsfRpcError as e:
        logger.error(f"MsfRpcError starting listener: {e}")
        return {"status": "error", "message": f"Error starting listener: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error starting listener")
        return {"status": "error", "message": f"Unexpected error starting listener: {str(e)}"}

@mcp.tool()
async def stop_job(job_id: int) -> Dict[str, Any]:
    """
    Stop a running Metasploit job (handler or exploit).
    """
    global _msf_client_instance
    logger.info(f"Stopping job {job_id}")
    try:
        job_id_str = str(job_id)
        jobs = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
        if job_id_str not in jobs:
            return {"status": "error", "message": f"Job {job_id} not found."}
        job_name = jobs.get(job_id_str, {}).get('name', 'Unknown')
        stop_result = await asyncio.to_thread(lambda: _msf_client_instance.jobs.stop(job_id_str))
        logger.debug(f"jobs.stop({job_id_str}) result: {stop_result}")
        await asyncio.sleep(0.5)
        jobs_after = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
        job_stopped = job_id_str not in jobs_after

        if job_stopped or (isinstance(stop_result, dict) and stop_result.get('result') == 'success'):
            logger.info(f"Successfully stopped job {job_id} ({job_name})")
            return {"status": "success", "message": f"Successfully stopped job {job_id}", "job_id": job_id, "job_name": job_name}
        else:
            logger.error(f"Failed to stop job {job_id}. API result: {stop_result}")
            return {"status": "error", "message": f"Failed to stop job {job_id}.", "job_id": job_id, "api_result": stop_result}
    except MsfRpcError as e:
        logger.error(f"MsfRpcError stopping job {job_id}: {e}")
        return {"status": "error", "message": f"Error stopping job: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error stopping job {job_id}.")
        return {"status": "error", "message": f"Unexpected error stopping job: {str(e)}"}


# --- FastAPI Application Setup ---
app = FastAPI(
    title="Metasploit MCP Server",
    description="Provides Metasploit functionality via the Model Context Protocol.",
    version="1.3.0", # Incremented version for sync/async fix
    lifespan=None
)
sse = SseServerTransport("/messages/")
app.router.routes.append(Mount("/messages", app=sse.handle_post_message))

@app.get("/sse", tags=["MCP"])
async def handle_sse(request: Request) -> None:
    async with sse.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
        await mcp._mcp_server.run(read_stream, write_stream, mcp._mcp_server.create_initialization_options())

@app.get("/healthz", tags=["Health"])
async def health_check():
    global _msf_client_instance
    if _msf_client_instance is None: raise HTTPException(status_code=503, detail="Metasploit client not initialized.")
    try:
        logger.debug("Executing health check MSF call...")
        version_info = await asyncio.to_thread(lambda: _msf_client_instance.core.version)
        logger.info(f"Health check successful. MSF Version: {version_info.get('version', 'N/A')}")
        return {"status": "ok", "msf_version": version_info}
    except (MsfRpcError, ConnectionError) as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Metasploit Service Unavailable: {e}")
    except Exception as e:
        logger.exception("Unexpected error during health check.")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during health check: {e}")

# --- Server Startup ---
if __name__ == "__main__":
    try: initialize_msf_client()
    except (ValueError, ConnectionError, RuntimeError) as e:
        logger.critical(f"Failed to initialize Metasploit client on startup: {e}. Server cannot start.")
        import sys; sys.exit(1)

    import argparse, socket, sys
    is_claude = not sys.stdin.isatty() if hasattr(sys.stdin, 'isatty') else False
    if is_claude:
        logger.info("Detected Claude Desktop launch. Using stdio transport.")
        mcp.run(transport="stdio")
    else:
        def find_available_port(start_port, max_attempts=10):
            for port in range(start_port, start_port + max_attempts):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    try: s.bind(('0.0.0.0', port)); return port
                    except socket.error: continue
            logger.warning(f"Could not find available port in range {start_port}-{start_port+max_attempts-1}")
            return start_port
        parser = argparse.ArgumentParser(description='Run Improved Metasploit MCP Server')
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
        parser.add_argument('--port', type=int, default=None, help='Port to listen on')
        parser.add_argument('--reload', action='store_true', help='Enable auto-reload (for development)')
        parser.add_argument('--find-port', action='store_true', help='Find an available port if specified one is in use')
        args = parser.parse_args()
        selected_port = args.port
        if selected_port is None or args.find_port:
            start_port = selected_port if selected_port is not None else 8085
            selected_port = find_available_port(start_port)
        logger.info(f"Starting server on {args.host}:{selected_port} (Reload: {args.reload})")
        uvicorn.run("__main__:app", host=args.host, port=selected_port, reload=args.reload, log_level="info")