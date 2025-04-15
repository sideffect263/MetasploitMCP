import asyncio
import base64 # For potentially returning payload bytes safely
import contextlib
import logging
import os
import shlex # Still needed for console command quoting
import pathlib
from datetime import datetime
# Removed subprocess import as msfvenom is no longer called directly
from typing import List, Dict, Any, Optional, Tuple, Union

# Third-party Libraries
import uvicorn
from fastapi import FastAPI, HTTPException
from mcp.server.fastmcp import FastMCP
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError, MsfConsole
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
        # Handle objects with a read method (like MsfConsole or Session)
        # Avoid reading here as it consumes output needed elsewhere
        logger.debug("safe_get_data encountered readable object, returning str representation.")
        return str(result)
    elif result is not None:
        try:
            return str(result)
        except Exception as e:
            logger.warning(f"Error converting result to string: {e}")
    return default

async def run_command_safely(console: Any, cmd: str, execution_timeout: Optional[int] = None) -> str:
    """
    Safely run a command on a Metasploit console and return the output.
    Handles reading data from the console object's read() method.

    Args:
        console: The Metasploit console object (MsfConsole).
        cmd: The command to run.
        execution_timeout: Optional specific timeout for this command's execution phase.

    Returns:
        The command output as a string.
    """
    try:
        logger.debug(f"Running console command: {cmd}")

        # Ensure console object has expected methods
        if not (hasattr(console, 'write') and hasattr(console, 'read') and hasattr(console, 'is_busy')):
            logger.error(f"Console object {type(console)} lacks required methods (write, read, is_busy).")
            raise TypeError("Unsupported console object type for command execution.")

        await asyncio.to_thread(console.write, cmd + '\n') # Ensure newline

        output_buffer = ""
        start_time = asyncio.get_event_loop().time()

        # Determine read timeout
        read_timeout = 10 # Default timeout
        is_long_command = cmd.strip().startswith(("run", "exploit", "check"))
        if is_long_command:
            read_timeout = 60
        if execution_timeout is not None:
            read_timeout = execution_timeout
            logger.debug(f"Using specified execution timeout: {read_timeout}s")

        check_interval = 0.2 # Seconds between checks
        last_data_time = start_time

        while True:
            await asyncio.sleep(check_interval)
            current_time = asyncio.get_event_loop().time()

            # Read available data without blocking indefinitely
            chunk_result = await asyncio.to_thread(console.read)
            chunk_data = ""

            # Check if console.read() returned the documented dictionary
            if isinstance(chunk_result, dict):
                chunk_data = chunk_result.get('data', '')
                is_busy_from_read = chunk_result.get('busy', True) # Assume busy if key missing
                # logger.debug(f"Read dict: data_len={len(chunk_data)}, busy={is_busy_from_read}")
            elif isinstance(chunk_result, str): # Fallback if it returns raw string
                chunk_data = chunk_result
                # logger.debug(f"Read raw string: len={len(chunk_data)}")
            # else: logger.debug(f"Read unexpected type: {type(chunk_result)}")

            if chunk_data:
                # logger.debug(f"Read chunk: {chunk_data}")
                output_buffer += chunk_data
                last_data_time = current_time # Reset timeout since we got data

            # Check for timeout based on *inactivity*
            if (current_time - last_data_time) > read_timeout:
                logger.debug(f"Read inactivity timeout ({read_timeout}s) reached for command '{cmd}'.")
                break

            # Check busy status explicitly - might help break loop faster
            try:
                # Only check busy status if it's likely relevant (e.g., after some initial wait/inactivity)
                if (current_time - last_data_time) > 1.0:
                    is_busy_explicit = await asyncio.to_thread(console.is_busy)
                    # logger.debug(f"Console busy status (explicit): {is_busy_explicit}")
                    if not is_busy_explicit:
                        # Double-check read buffer one last time after busy reports false
                        final_chunk_result = await asyncio.to_thread(console.read)
                        final_chunk_data = final_chunk_result.get('data', '') if isinstance(final_chunk_result, dict) else (final_chunk_result if isinstance(final_chunk_result, str) else '')
                        if final_chunk_data:
                           output_buffer += final_chunk_data
                        logger.debug("Console reported not busy and final read was empty, ending read loop.")
                        break
            except Exception as busy_err:
                 # logger.warning(f"Could not check console busy status: {busy_err}")
                 pass # Ignore busy check errors silently for now

        logger.debug(f"Final output for '{cmd}' (length {len(output_buffer)}):\n{output_buffer.strip()}")
        return output_buffer.strip()

    except Exception as e:
        logger.exception(f"Error executing command '{cmd}'") # Log full traceback
        raise RuntimeError(f"Failed executing command '{cmd}': {e}") from e


def initialize_msf_client():
    """Initializes the global Metasploit RPC client instance."""
    global _msf_client_instance
    if _msf_client_instance is not None:
        return _msf_client_instance

    logger.info("Attempting to initialize Metasploit RPC client...")

    msf_password = os.environ.get('MSF_PASSWORD', 'yourpassword') # Default password
    msf_server = os.getenv('MSF_SERVER', '127.0.0.1')
    msf_port_str = os.getenv('MSF_PORT', '55553')
    msf_ssl_str = os.getenv('MSF_SSL', 'false')

    try:
        msf_port = int(msf_port_str)
        msf_ssl = msf_ssl_str.lower() == 'true'
        client = MsfRpcClient(
            password=msf_password,
            server=msf_server,
            port=msf_port,
            ssl=msf_ssl
        )
        # Test connection during initialization
        version_info = client.core.version # Access as property
        logger.info(f"Successfully connected to Metasploit RPC at {msf_server}:{msf_port} (SSL: {msf_ssl}), version: {version_info.get('version', 'unknown')}")
        _msf_client_instance = client
        return _msf_client_instance
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid MSF connection parameters (PORT: {msf_port_str}, SSL: {msf_ssl_str}). Error: {e}")
        raise ValueError(f"Invalid MSF connection parameters") from e
    except MsfRpcError as e:
        logger.error(f"Failed to connect or authenticate to Metasploit RPC ({msf_server}:{msf_port}, SSL: {msf_ssl}): {e}")
        raise ConnectionError(f"Failed to connect/authenticate to Metasploit RPC: {e}") from e
    except Exception as e:
        logger.error(f"An unexpected error occurred during MSF client initialization: {e}", exc_info=True)
        raise RuntimeError(f"Unexpected error initializing MSF client: {e}") from e

@contextlib.asynccontextmanager
async def get_msf_console() -> MsfConsole:
    """Async context manager for creating and destroying an MSF console."""
    global _msf_client_instance
    if _msf_client_instance is None:
        raise ConnectionError("Metasploit client not initialized.")

    console_object: Optional[MsfConsole] = None
    console_id_str: Optional[str] = None
    try:
        logger.debug("Attempting to create temporary console...")
        # Create console object directly
        console_object = await asyncio.to_thread(lambda: _msf_client_instance.consoles.console())
        # logger.debug(f"Console creation returned type: {type(console_object)}, value: {console_object}")

        # Get ID using .cid attribute
        if isinstance(console_object, MsfConsole) and hasattr(console_object, 'cid'):
            console_id_val = getattr(console_object, 'cid')
            console_id_str = str(console_id_val) if console_id_val is not None else None
            if not console_id_str:
                raise ValueError(".cid attribute is present but empty or None.")
            logger.info(f"Successfully obtained console object and extracted ID: {console_id_str}")
            # Read initial prompt/banner to clear buffer (optional but can help)
            await asyncio.sleep(0.1)
            initial_read = await asyncio.to_thread(console_object.read)
            logger.debug(f"Initial console read (clearing buffer): {initial_read}")
            yield console_object # Yield the validated console object
        else:
            # This case should ideally not happen if .console() works as expected
            logger.error(f"client.consoles.console() did not return expected MsfConsole object with .cid. Got type: {type(console_object)}")
            raise MsfRpcError(f"Unexpected result from console creation: {console_object}")

    except MsfRpcError as e:
        logger.error(f"MsfRpcError during console operation: {e}")
        raise MsfRpcError(f"Error creating/accessing MSF console: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during console creation/setup")
        raise RuntimeError(f"Unexpected error during console operation: {e}") from e
    finally:
        # Destruction Logic
        if console_id_str and _msf_client_instance: # Check client still exists
            try:
                logger.info(f"Attempting to destroy Metasploit console (ID: {console_id_str})...")
                destroy_result = await asyncio.to_thread(
                    lambda: _msf_client_instance.consoles.destroy(console_id_str)
                )
                logger.debug(f"Console destroy result: {destroy_result}")
            except Exception as e:
                # Log error but don't prevent function exit
                logger.error(f"Error destroying MSF console {console_id_str}: {e}")
        elif console_object and not console_id_str:
             logger.warning("Console object created but no valid ID obtained, cannot explicitly destroy.")
        # else: logger.debug("No console ID obtained, skipping destruction.")


# --- MCP Server Initialization ---
mcp = FastMCP("Metasploit Tools Improved")

# --- MCP Tool Definitions ---

@mcp.tool()
async def list_exploits(search_term: str = "") -> List[str]:
    """
    List available Metasploit exploits, optionally filtered by search term.
    Args:
        search_term: Optional term to filter exploits.
    Returns:
        List of exploit names matching the search term (max 200 if filtered, 100 otherwise).
    """
    global _msf_client_instance
    if _msf_client_instance is None: return ["Error: MSF client not initialized."]
    logger.info(f"Listing exploits (search term: '{search_term or 'None'}')")
    try:
        exploits = await asyncio.to_thread(lambda: _msf_client_instance.modules.exploits)
        logger.debug(f"Retrieved {len(exploits)} total exploits from MSF.")
        if search_term:
            filtered_exploits = [e for e in exploits if search_term.lower() in e.lower()]
            count = len(filtered_exploits)
            limit = 200
            logger.info(f"Found {count} exploits matching '{search_term}'. Returning max {limit}.")
            return filtered_exploits[:limit]
        else:
            limit = 100
            logger.info(f"No search term provided, returning first {limit} exploits.")
            return exploits[:limit]
    except MsfRpcError as e:
        logger.error(f"Failed to list exploits from Metasploit: {e}")
        return [f"Error listing exploits: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing exploits.")
        return [f"Unexpected error listing exploits: {e}"]

@mcp.tool()
async def list_payloads(platform: str = "", arch: str = "") -> List[str]:
    """
    List available Metasploit payloads, optionally filtered by platform and/or architecture.
    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux', 'python').
        arch: Optional architecture filter (e.g., 'x86', 'x64', 'cmd').
    Returns:
        List of payload names matching filters (max 100).
    """
    global _msf_client_instance
    if _msf_client_instance is None: return ["Error: MSF client not initialized."]
    logger.info(f"Listing payloads (platform: '{platform or 'Any'}', arch: '{arch or 'Any'}')")
    try:
        payloads = await asyncio.to_thread(lambda: _msf_client_instance.modules.payloads)
        logger.debug(f"Retrieved {len(payloads)} total payloads from MSF.")
        filtered = payloads
        if platform:
            # Match platform at the start of the payload path segment
            filtered = [p for p in filtered if p.lower().startswith(platform.lower() + '/')]
        if arch:
            # Match architecture anywhere in the payload path (e.g., windows/x64/...)
            filtered = [p for p in filtered if f"/{arch.lower()}/" in p.lower() or p.lower().startswith(arch.lower() + '/')]
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


# --- Rewritten Payload Generation Tool ---
@mcp.tool()
async def generate_payload(
    payload_type: str,
    format_type: str,
    options: Dict[str, Any] = None, # e.g., {"LHOST": "1.2.3.4", "LPORT": 4444}
    # Removed direct lhost/lport, pass them in options dict
    # Added encoder options etc.
    encoder: Optional[str] = None,
    iterations: int = 0,
    bad_chars: str = "",
    nop_sled_size: int = 0,
    template_path: Optional[str] = None,
    keep_template: bool = False,
    force_encode: bool = False,
    output_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a Metasploit payload using the RPC API (payload.payload_generate).
    Saves the generated payload to a file on the server if generation is successful.

    Args:
        payload_type: Type of payload (e.g., windows/meterpreter/reverse_tcp).
        format_type: Output format (raw, exe, python, etc.).
        options: Dictionary of required payload options (e.g., LHOST, LPORT).
        encoder: Optional encoder to use.
        iterations: Optional number of encoding iterations.
        bad_chars: Optional string of bad characters to avoid (e.g., '\\x00\\x0a\\x0d').
        nop_sled_size: Optional size of NOP sled.
        template_path: Optional path to an executable template.
        keep_template: Keep the template working (requires template_path).
        force_encode: Force encoding even if not needed by bad chars.
        output_filename: Optional desired filename (without path). If None, a default name is generated.

    Returns:
        Dictionary containing status, message, payload size/info,
        and potentially the server-side path where the payload was saved.
    """
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    logger.info(f"Generating payload '{payload_type}' (Format: {format_type}) via RPC. Options: {options}")
    payload_options = options or {}

    try:
        # Get the payload module object
        payload = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('payload', payload_type))
        logger.debug(f"Retrieved payload module object for '{payload_type}'")

        # Set payload-specific required options (like LHOST/LPORT)
        for key, value in payload_options.items():
             # Basic type guessing (can be refined if needed)
            if isinstance(value, str):
                if value.isdigit(): value = int(value)
                elif value.lower() in ('true', 'false'): value = value.lower() == 'true'
            await asyncio.to_thread(lambda k=key, v=value: payload.__setitem__(k, v))
            logger.debug(f"Set payload option {key}={value}")

        # Set generation options using payload.runoptions - FIXED: Set individual dictionary entries
        if format_type:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('Format', format_type))
        if encoder:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('Encoder', encoder))
        if iterations > 0:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('Iterations', iterations))
        if bad_chars:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('BadChars', bad_chars))
        if nop_sled_size > 0:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('NopSledSize', nop_sled_size))
        if template_path:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('Template', template_path))
        if keep_template:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('KeepTemplateWorking', True))
        if force_encode:
            await asyncio.to_thread(lambda: payload.runoptions.__setitem__('ForceEncode', True))

        logger.debug(f"Set payload generation options in runoptions dictionary")

        # Generate the payload bytes
        logger.info("Calling payload_generate()...")
        raw_payload_bytes = await asyncio.to_thread(payload.payload_generate) # Expects bytes

        if isinstance(raw_payload_bytes, bytes):
            payload_size = len(raw_payload_bytes)
            logger.info(f"Payload generation successful. Size: {payload_size} bytes.")
            
            # Determine save directory
            save_directory = os.environ.get('PAYLOAD_SAVE_DIR')
            if not save_directory:
                # Default to ~/payloads
                save_directory = str(pathlib.Path.home() / "payloads")
            
            # Ensure directory exists
            try:
                os.makedirs(save_directory, exist_ok=True)
                logger.debug(f"Ensuring payload directory exists: {save_directory}")
            except OSError as e:
                logger.error(f"Failed to create payload save directory {save_directory}: {e}")
                return {
                    "status": "error", 
                    "message": f"Payload generated successfully ({payload_size} bytes) but could not create save directory: {e}",
                    "payload_size": payload_size, 
                    "format": format_type
                }
            
            # Determine filename
            final_filename = None
            if output_filename:
                # Basic sanitization - allow only alphanumeric, underscore, hyphen, dot
                import re
                sanitized = re.sub(r'[^a-zA-Z0-9_\-.]', '_', output_filename)
                if sanitized:
                    final_filename = sanitized
            
            if not final_filename:
                # Create default filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_payload_type = payload_type.replace('/', '_')
                final_filename = f"payload_{safe_payload_type}_{timestamp}.{format_type}"
            
            # Full save path
            save_path = os.path.join(save_directory, final_filename)
            
            # Write payload to file
            try:
                with open(save_path, "wb") as f:
                    f.write(raw_payload_bytes)
                logger.info(f"Payload saved to {save_path}")
                return {
                    "status": "success", 
                    "message": f"Payload '{payload_type}' generated successfully and saved.", 
                    "payload_size": payload_size, 
                    "format": format_type,
                    "server_save_path": save_path
                }
            except IOError as e:
                logger.error(f"Failed to write payload to {save_path}: {e}")
                return {
                    "status": "error", 
                    "message": f"Payload generated but failed to save to file: {e}", 
                    "payload_size": payload_size, 
                    "format": format_type
                }

        elif isinstance(raw_payload_bytes, str): # Should return bytes, but handle error strings
             logger.error(f"Payload generation failed. payload_generate returned string: {raw_payload_bytes}")
             return {"status": "error", "message": f"Payload generation failed: {raw_payload_bytes}"}
        else:
            logger.error(f"Payload generation failed. Unexpected return type: {type(raw_payload_bytes)}")
            return {"status": "error", "message": "Payload generation failed. Unexpected return type from API."}

    except MsfRpcError as e:
        if "Invalid Payload" in str(e):
            logger.error(f"Invalid payload type specified: {payload_type}")
            return {"status": "error", "message": f"Invalid payload type: {payload_type}"}
        elif "Missing required" in str(e) or "Invalid option" in str(e):
             logger.error(f"Missing or invalid options for payload {payload_type}: {e}")
             return {"status": "error", "message": f"Missing/invalid options for payload {payload_type}: {str(e)}", "required_options": getattr(payload, 'missing_required', [])}
        logger.error(f"MsfRpcError generating payload {payload_type}: {e}")
        return {"status": "error", "message": f"Error generating payload: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error during payload generation for '{payload_type}'.")
        return {"status": "error", "message": "An unexpected error occurred during payload generation.", "error_details": str(e)}

@mcp.tool()
async def run_exploit(
    module_name: str,
    options: Dict[str, Any],
    payload_name: Optional[str] = None, # Renamed for clarity
    payload_options: Optional[Dict[str, Any]] = None,
    run_as_job: bool = True, # Defaulting to True for exploits seems safer
    timeout_seconds: int = 300
) -> Dict[str, Any]:
    """
    Run a Metasploit exploit module with specified options.
    Handles both synchronous (run_as_job=False) and asynchronous (run_as_job=True) execution.
    Uses the payload object passing method for asynchronous runs if payload_options are set.

    Args:
        module_name: Name of the exploit module (e.g., 'windows/smb/ms17_010_eternalblue').
        options: Dictionary of exploit module options (e.g., {'RHOSTS': '192.168.1.1'}).
        payload_name: Name of the payload to use (e.g., 'windows/meterpreter/reverse_tcp').
        payload_options: Dictionary of payload options (e.g., {'LHOST': '192.168.1.100', 'LPORT': 4444}).
        run_as_job: If True, run as background job. If False, run synchronously.
        timeout_seconds: Max time for synchronous run via console.

    Returns:
        Dictionary with execution results or error details.
    """
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    logger.info(f"Running exploit {module_name}. Run as job: {run_as_job}. Options: {options}, Payload: {payload_name}, Payload Opts: {payload_options}")

    if '/' not in module_name: module_name = f"exploit/{module_name}"
    elif not module_name.startswith('exploit/'):
        logger.error(f"Invalid exploit module name: {module_name}")
        return {"status": "error", "message": f"Invalid exploit module name: {module_name}."}

    module_options = options or {}
    final_payload_options = payload_options or {}
    payload_to_pass: Union[str, object, None] = payload_name # Default to string

    try:
        # --- Get the exploit module object ---
        base_module_name = module_name.replace('exploit/', '', 1)
        module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('exploit', base_module_name))
        logger.debug(f"Retrieved exploit module object for '{base_module_name}'")

        # --- Set exploit options ---
        for k, v in module_options.items():
            if isinstance(v, str):
                if v.isdigit(): v = int(v)
                elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
            await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))
            # logger.debug(f"Set exploit option {k}={v}")

        # --- Prepare payload object if needed (for async execution) ---
        if run_as_job and payload_name and final_payload_options:
            logger.debug(f"Preparing payload object '{payload_name}' with options for async execution.")
            payload_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('payload', payload_name))
            for k, v in final_payload_options.items():
                if isinstance(v, str):
                    if v.isdigit(): v = int(v)
                    elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
                await asyncio.to_thread(lambda key=k, value=v: payload_obj.__setitem__(key, value))
                # logger.debug(f"Set payload object option {k}={v}")
            payload_to_pass = payload_obj # Pass the configured object
            logger.info(f"Executing exploit with configured payload object.")
        elif run_as_job and payload_name:
            # Pass payload name string if no specific options needed for the object method
             logger.info(f"Executing exploit with payload name string '{payload_name}'.")
             payload_to_pass = payload_name


        # --- Execute ---
        if run_as_job:
            # --- Asynchronous Execution (Run as Job) ---
            logger.info(f"Calling module_obj.execute(payload={type(payload_to_pass)}) for background job.")
            exec_result = await asyncio.to_thread(lambda: module_obj.execute(payload=payload_to_pass))
            logger.info(f"module_obj.execute() result: {exec_result}")

            # Process job result
            if isinstance(exec_result, dict):
                job_id = exec_result.get('job_id')
                uuid = exec_result.get('uuid')
                if 'error' in exec_result and exec_result['error']:
                    error_message = f"Failed to start exploit job: {exec_result.get('error_message', exec_result.get('error_string', 'Unknown error'))}"
                    logger.error(error_message)
                    return {"status": "error", "message": error_message, "module": module_name}
                elif job_id is not None:
                    message = f"Exploit module {module_name} started as job {job_id}."
                    # Check for associated session quickly
                    await asyncio.sleep(1.5) # Give session time to potentially appear
                    sessions_list = await asyncio.to_thread(lambda: _msf_client_instance.sessions.list)
                    found_session_id = None
                    for s_id, s_info in sessions_list.items():
                         # Ensure s_id is treated as string key for comparison if needed, RPC might return int/str
                        s_id_str = str(s_id)
                        if isinstance(s_info, dict) and s_info.get('exploit_uuid') == uuid:
                            found_session_id = s_id # Keep original type from list keys
                            message += f" Session {found_session_id} created."
                            logger.info(f"Found session {found_session_id} matching exploit UUID {uuid}")
                            break
                    return {
                        "status": "success", "message": message, "job_id": job_id, "uuid": uuid,
                        "session_id": found_session_id, "module": module_name, "options": module_options,
                        "payload_name": payload_name, "payload_options": final_payload_options
                    }
                else:
                    logger.warning(f"Exploit job executed but no job_id returned: {exec_result}")
                    return {"status": "unknown", "message": "Exploit executed, but no job ID returned.", "result": exec_result, "module": module_name}
            else:
                logger.error(f"Unexpected result format from exploit execute: {exec_result}")
                return {"status": "error", "message": f"Unexpected result format from exploit execution: {exec_result}", "module": module_name}

        else:
            # --- Synchronous Execution (via Console) ---
            # TODO: Consider alternative using console.run_module_with_output(module_obj, payload=payload_name)
            logger.info(f"Executing {module_name} synchronously via console.")
            async with get_msf_console() as console:
                setup_commands = [f"use {module_name}"]
                # Add exploit options
                for key, value in module_options.items():
                    val_str = str(value)
                    if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                         val_str = shlex.quote(val_str)
                    setup_commands.append(f"set {key} {val_str}")

                # Add payload and payload options (for console mode, set directly)
                if payload_name:
                    setup_commands.append(f"set PAYLOAD {payload_name}")
                    for key, value in final_payload_options.items():
                        val_str = str(value)
                        if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                             val_str = shlex.quote(val_str)
                        setup_commands.append(f"set {key} {val_str}")

                final_command = "exploit" # Synchronous command

                # Execute setup commands
                for cmd in setup_commands:
                    logger.debug(f"Running setup command: {cmd}")
                    setup_output = await run_command_safely(console, cmd, execution_timeout=15)
                    if "[-] Error setting" in setup_output or "Invalid option" in setup_output: # Check for setup errors
                         error_msg = f"Error during setup command '{cmd}': {setup_output}"
                         logger.error(error_msg)
                         return {"status": "error", "message": error_msg}
                    await asyncio.sleep(0.1) # Small delay between setup commands

                # Execute the final command
                logger.info(f"Running final command: {final_command}")
                module_output = await run_command_safely(console, final_command, execution_timeout=timeout_seconds)
                logger.debug(f"Synchronous execution output length: {len(module_output)}")

                # Try to parse session ID from output
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
                             if session_id: break
                         except (ValueError, IndexError): pass # Ignore parsing errors

                return {
                    "status": "success",
                    "message": f"Exploit module {module_name} completed synchronously.",
                    "module_output": module_output,
                    "session_id_detected": session_id,
                    "module": module_name,
                    "options": module_options,
                    "payload_name": payload_name,
                    "payload_options": final_payload_options
                }

    except MsfRpcError as e:
        if "Unknown module" in str(e) or "failed to load" in str(e).lower():
            logger.error(f"Exploit module {module_name} not found/failed load: {e}")
            return {"status": "error", "message": f"Exploit module {module_name} not found or failed to load."}
        elif "Invalid Payload" in str(e):
            logger.error(f"Invalid payload specified for exploit {module_name}: {payload_name}")
            return {"status": "error", "message": f"Invalid payload specified: {payload_name}"}
        logger.error(f"MsfRpcError running exploit {module_name}: {e}")
        return {"status": "error", "message": f"Error running exploit: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error running exploit {module_name}")
        return {"status": "error", "message": f"Unexpected error running exploit: {str(e)}"}


@mcp.tool()
async def run_post_module(
    module_name: str,
    session_id: int,
    options: Dict[str, Any] = None,
    run_as_job: bool = True,
    timeout_seconds: int = 300
) -> Dict[str, Any]:
    """Run a Metasploit post-exploitation module against a session."""
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    if '/' not in module_name: module_name = f"post/{module_name}"
    elif not module_name.startswith('post/'): logger.warning(f"Running non-post module '{module_name}' with run_post_module tool.")

    logger.info(f"Running post module {module_name} on session {session_id}. Run as job: {run_as_job}")
    module_options = options or {}
    module_options['SESSION'] = session_id # Ensure session is always set

    try:
        # --- Get the post module object ---
        base_module_name = module_name # Assumes full path now
        if base_module_name.startswith('post/'):
            base_module_name = base_module_name.replace('post/', '', 1)

        module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('post', base_module_name))
        logger.debug(f"Retrieved module object for '{base_module_name}'")

        # --- Set module options ---
        for k, v in module_options.items():
            if isinstance(v, str):
                if v.isdigit(): v = int(v)
                elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
            # Ensure SESSION is int
            if k == 'SESSION': v = int(v)
            await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))
            # logger.debug(f"Set post module option {k}={v}")

        # --- Execute ---
        if run_as_job:
            # --- Asynchronous Execution (Run as Job) ---
            logger.info(f"Executing {module_name} as background job.")
            exec_result = await asyncio.to_thread(lambda: module_obj.execute()) # Post modules don't take payload arg
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
                 else: # Attempt UUID matching if no job_id
                     if uuid:
                         await asyncio.sleep(1.0)
                         jobs = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
                         for jid, jinfo in jobs.items():
                             if isinstance(jinfo, dict) and jinfo.get('uuid') == uuid:
                                 logger.info(f"Found matching job {jid} for uuid {uuid}")
                                 return {"status": "success", "message": f"Post module {module_name} likely started as job {jid}", "job_id": jid, "uuid": uuid, "module": module_name, "session_id": session_id}
                     logger.warning(f"Post module job executed but no job_id returned/matched: {exec_result}")
                     return {"status": "unknown", "message": "Post module execution finished, but job ID missing/unmatched.", "result": exec_result, "module": module_name, "session_id": session_id}
            else:
                 logger.error(f"Unexpected result format from post module execute: {exec_result}")
                 return {"status": "error", "message": f"Unexpected result format from post execution: {exec_result}", "module": module_name}

        else:
            # --- Synchronous Execution (via Console) ---
            # TODO: Consider alternative using console.run_module_with_output(module_obj)
            logger.info(f"Executing {module_name} synchronously via console.")
            async with get_msf_console() as console:
                setup_commands = [f"use {module_name}"]
                # Add options
                for key, value in module_options.items():
                    val_str = str(value)
                    if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                        val_str = shlex.quote(val_str)
                    setup_commands.append(f"set {key} {val_str}")

                final_command = "run" # Synchronous command

                # Execute setup commands
                for cmd in setup_commands:
                    logger.debug(f"Running setup command: {cmd}")
                    setup_output = await run_command_safely(console, cmd, execution_timeout=15)
                    if "[-] Error setting" in setup_output or "Invalid option" in setup_output:
                         error_msg = f"Error during setup command '{cmd}': {setup_output}"
                         logger.error(error_msg)
                         return {"status": "error", "message": error_msg}
                    await asyncio.sleep(0.1)

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
        if "Invalid Session" in str(e) or "Session ID is not valid" in str(e): return {"status": "error", "message": f"Invalid Session ID: {session_id} for module {module_name}."}
        logger.error(f"MsfRpcError running post module {module_name}: {e}")
        return {"status": "error", "message": f"Error running post module: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error running post module {module_name}")
        return {"status": "error", "message": f"Unexpected error running post module: {str(e)}"}


@mcp.tool()
async def run_auxiliary_module(
    module_name: str,
    options: Dict[str, Any],
    run_as_job: bool = False, # Default False for scanners makes sense
    timeout_seconds: int = 300
) -> Dict[str, Any]:
    """Run a Metasploit auxiliary module."""
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    if '/' not in module_name: module_name = f"auxiliary/{module_name}"
    elif not module_name.startswith('auxiliary/'):
        return {"status": "error", "message": f"Invalid auxiliary module name: {module_name}."}

    logger.info(f"Running auxiliary module {module_name}. Run as job: {run_as_job}. Options: {options}")
    module_options = options or {}

    try:
        # --- Get the auxiliary module object ---
        base_module_name = module_name.replace('auxiliary/', '', 1)
        module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('auxiliary', base_module_name))
        logger.debug(f"Retrieved module object for '{base_module_name}'")

        # --- Set module options ---
        for k, v in module_options.items():
            if isinstance(v, str):
                if v.isdigit(): v = int(v)
                elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
            await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))
            # logger.debug(f"Set auxiliary module option {k}={v}")

        # --- Execute ---
        if run_as_job:
            # --- Asynchronous Execution (Run as Job) ---
            logger.info(f"Executing {module_name} as background job.")
            exec_result = await asyncio.to_thread(lambda: module_obj.execute()) # Aux modules don't take payload arg
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
                else: # Attempt UUID matching
                    if uuid:
                        await asyncio.sleep(1.0)
                        jobs = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
                        for jid, jinfo in jobs.items():
                            if isinstance(jinfo, dict) and jinfo.get('uuid') == uuid:
                                logger.info(f"Found matching job {jid} for uuid {uuid}")
                                return {"status": "success", "message": f"Auxiliary module {module_name} likely started as job {jid}", "job_id": jid, "uuid": uuid, "module": module_name, "options": options}
                    logger.warning(f"Auxiliary module job executed but no job_id returned/matched: {exec_result}")
                    return {"status": "unknown", "message": "Auxiliary module executed, but job ID missing/unmatched.", "result": exec_result, "module": module_name, "options": options}
            else:
                logger.error(f"Unexpected result format from auxiliary module execute: {exec_result}")
                return {"status": "error", "message": f"Unexpected result format from auxiliary execution: {exec_result}", "module": module_name}
        else:
            # --- Synchronous Execution (via Console) ---
            # TODO: Consider alternative using console.run_module_with_output(module_obj)
            logger.info(f"Executing {module_name} synchronously via console.")
            async with get_msf_console() as console:
                setup_commands = [f"use {module_name}"]
                for key, value in module_options.items():
                    val_str = str(value)
                    if isinstance(value, str) and (' ' in val_str or '"' in val_str or "'" in val_str):
                        val_str = shlex.quote(val_str)
                    setup_commands.append(f"set {key} {val_str}")

                final_command = "run"

                for cmd in setup_commands:
                    logger.debug(f"Running setup command: {cmd}")
                    setup_output = await run_command_safely(console, cmd, execution_timeout=15)
                    if "[-] Error setting" in setup_output or "Invalid option" in setup_output:
                        error_msg = f"Error during setup command '{cmd}': {setup_output}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg}
                    await asyncio.sleep(0.1)

                logger.info(f"Running final command: {final_command}")
                module_output = await run_command_safely(console, final_command, execution_timeout=timeout_seconds)
                logger.debug(f"Synchronous execution output length: {len(module_output)}")

                return {
                    "status": "success",
                    "message": f"Auxiliary module {module_name} completed synchronously.",
                    "module_output": module_output,
                    "module": module_name,
                    "options": options
                }

    except MsfRpcError as e:
        if "Unknown module" in str(e): return {"status": "error", "message": f"Auxiliary module {module_name} not found."}
        logger.error(f"MsfRpcError running auxiliary module {module_name}: {e}")
        return {"status": "error", "message": f"Error running auxiliary module: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error running auxiliary module {module_name}")
        return {"status": "error", "message": f"Unexpected error running auxiliary module: {str(e)}"}

@mcp.tool()
async def list_active_sessions() -> Dict[str, Any]:
    """List active Metasploit sessions."""
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}
    logger.info("Listing active Metasploit sessions.")
    try:
        sessions_dict = await asyncio.to_thread(lambda: _msf_client_instance.sessions.list)
        if not isinstance(sessions_dict, dict):
            logger.error(f"Expected dict from sessions.list, got {type(sessions_dict)}")
            return {"status": "error", "message": f"Unexpected data type for sessions list: {type(sessions_dict)}"}
        logger.info(f"Found {len(sessions_dict)} active sessions.")
        # Convert keys to strings for consistent JSON if they are integers
        sessions_dict_str_keys = {str(k): v for k, v in sessions_dict.items()}
        return {"status": "success", "sessions": sessions_dict_str_keys}
    except MsfRpcError as e:
        logger.error(f"Failed to list sessions: {e}")
        return {"status": "error", "message": f"Error listing sessions: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error listing sessions.")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

@mcp.tool()
async def send_session_command(
    session_id: int, # Keep as int for input clarity
    command: str,
    timeout_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Send a command to an active Metasploit session and get output.
    Uses simple write/read loop. Consider session.run_with_output for more robustness.

    Args:
        session_id: ID of the target session.
        command: Command string to execute in the session.
        timeout_seconds: Maximum time to wait for the command to complete.

    Returns:
        Dictionary with status and command output or error details.
    """
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    logger.info(f"Sending command to session {session_id}: '{command}'")
    try:
        session_id_str = str(session_id) # Convert to string for library interaction
        session = await asyncio.to_thread(lambda: _msf_client_instance.sessions.session(session_id_str))

        if not session: # Check if session object was retrieved
             # Double check list in case session ended between list and access
             current_sessions = await asyncio.to_thread(lambda: _msf_client_instance.sessions.list)
             if session_id_str not in current_sessions:
                  logger.error(f"Session {session_id} not found in current list.")
                  return {"status": "error", "message": f"Session {session_id} not found."}
             else:
                  # This case indicates an issue with sessions.session(id) retrieval itself
                  logger.error(f"Session {session_id} exists in list but sessions.session() failed.")
                  return {"status": "error", "message": f"Error retrieving session {session_id} object."}

        # --- Use session.write and session.read loop ---
        # TODO: Consider refactoring using session.run_with_output(command, terminating_strs=[...])
        # which might be more robust for handling command completion detection.
        logger.debug(f"Writing command to session {session_id}: {command}")
        await asyncio.to_thread(session.write, command + '\n')

        output_buffer = ""
        start_time = asyncio.get_event_loop().time()
        read_interval = 0.2 # Check frequently
        last_read_time = start_time
        no_data_timeout = 10 # How long to wait with NO data before assuming completion (if not timed out overall)

        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            await asyncio.sleep(read_interval)
            current_time = asyncio.get_event_loop().time()
            read_data = await asyncio.to_thread(session.read) # Returns string directly for sessions

            if read_data:
                # logger.debug(f"Session {session_id} read: {read_data}")
                output_buffer += read_data
                last_read_time = current_time # Reset inactivity timer

                # Optional: Check for prompts to break early (can be fragile)
                # stripped_output = output_buffer.strip()
                # if any(stripped_output.endswith(p) for p in ["meterpreter >", "> \n", "# \n", "$ \n"]):
                #    logger.debug("Detected potential prompt, finishing read early.")
                #    break
            elif (current_time - last_read_time) > no_data_timeout:
                 logger.debug(f"No data received from session {session_id} for {no_data_timeout}s, assuming command finished.")
                 break # Assume finished if no data for a while

        # --- Determine final status ---
        final_status = "success"
        message = "Command executed."
        if (asyncio.get_event_loop().time() - start_time) >= timeout_seconds:
             if output_buffer:
                 logger.warning(f"Command '{command}' potentially timed out after {timeout_seconds}s on session {session_id}. Returning partial output.")
                 final_status = "timeout"
                 message = f"Command potentially timed out after {timeout_seconds} seconds. Returning collected output."
             else:
                 logger.warning(f"Command '{command}' timed out after {timeout_seconds}s on session {session_id}. No output received.")
                 final_status = "timeout"
                 message = f"Command execution timed out after {timeout_seconds} seconds. No output received."

        # Limit output size for response
        output_preview = output_buffer[:2000] + ('...' if len(output_buffer) > 2000 else '')
        return {"status": final_status, "message": message, "output": output_preview}

    except MsfRpcError as e:
        # Check specific errors if needed (e.g., session invalid errors)
        if "Session ID is not valid" in str(e):
             logger.error(f"RPC Error: Session {session_id} is invalid: {e}")
             return {"status": "error", "message": f"Session {session_id} is not valid."}
        logger.error(f"MsfRpcError sending command to session {session_id}: {e}")
        return {"status": "error", "message": f"Error interacting with session {session_id}: {str(e)}"}
    except KeyError: # Library might raise this if session ID is missing internally
        logger.error(f"Session {session_id} likely not found (KeyError).")
        return {"status": "error", "message": f"Session {session_id} not found."}
    except Exception as e:
        logger.exception(f"Unexpected error sending command to session {session_id}.")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}


# --- Tools wrapping send_session_command ---
# These tools rely on send_session_command's behavior.
# Consider using session.run_with_output within them directly for more specific termination conditions if needed.

async def _verify_meterpreter_session(session_id: int) -> Tuple[Optional[Dict], Optional[str]]:
    """Helper to check if a session exists and is Meterpreter."""
    global _msf_client_instance
    if _msf_client_instance is None: return None, "MSF client not initialized."
    try:
        session_id_str = str(session_id)
        # Check list first for existence
        current_sessions = await asyncio.to_thread(lambda: _msf_client_instance.sessions.list)
        if session_id_str not in current_sessions:
             logger.error(f"Session {session_id} not found in list.")
             return None, f"Session {session_id} not found."

        session_info = current_sessions[session_id_str] # Use info from list
        if not isinstance(session_info, dict):
             logger.error(f"Unexpected session info format for {session_id}: {session_info}")
             return None, f"Error retrieving session info for {session_id}."

        session_type = session_info.get('type')
        if session_type != 'meterpreter':
            logger.warning(f"Session {session_id} is not Meterpreter (type: {session_type}).")
            return None, f"Session {session_id} is type '{session_type}', requires Meterpreter."

        return session_info, None # Return session info if meterpreter, no error
    except MsfRpcError as e:
        logger.error(f"RPC error checking session {session_id} type: {e}")
        return None, f"RPC error checking session {session_id}."
    except Exception as e:
        logger.exception(f"Unexpected error checking session {session_id} type.")
        return None, f"Unexpected error checking session {session_id}."

@mcp.tool()
async def get_system_info(session_id: int) -> Dict[str, Any]:
    """Get system information from a Meterpreter session."""
    logger.info(f"Getting system info for session {session_id}")
    session_info, error = await _verify_meterpreter_session(session_id)
    if error: return {"status": "error", "message": error}

    sysinfo_result = await send_session_command(session_id, 'sysinfo', timeout_seconds=30)

    if sysinfo_result.get("status") in ["success", "timeout"]:
        raw_output = sysinfo_result.get("output", "")
        logger.info(f"Received sysinfo output (Status: {sysinfo_result.get('status')}). Parsing...")
        parsed_info = {}
        for line in raw_output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                parsed_info[key.strip()] = value.strip()
        return {"status": "success", "sysinfo": parsed_info, "raw_output": raw_output, "command_status": sysinfo_result.get("status")}
    else:
        logger.error(f"Failed to run 'sysinfo' via send_session_command: {sysinfo_result.get('message')}")
        return sysinfo_result

@mcp.tool()
async def get_user_id(session_id: int) -> Dict[str, Any]:
    """Get the current user ID from a Meterpreter session."""
    logger.info(f"Getting user ID for session {session_id}")
    session_info, error = await _verify_meterpreter_session(session_id)
    if error: return {"status": "error", "message": error}

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
        return getuid_result

@mcp.tool()
async def list_processes(session_id: int) -> Dict[str, Any]:
    """List running processes via a Meterpreter session."""
    logger.info(f"Listing processes for session {session_id}")
    session_info, error = await _verify_meterpreter_session(session_id)
    if error: return {"status": "error", "message": error}

    ps_result = await send_session_command(session_id, 'ps', timeout_seconds=45)

    if ps_result.get("status") in ["success", "timeout"]:
        raw_output = ps_result.get("output", "")
        logger.info(f"Received ps output (Status: {ps_result.get('status')}). Parsing...")
        lines = raw_output.strip().splitlines()
        processes = []
        header_found = False
        pid_col, ppid_col, name_col = -1, -1, -1 # Basic columns

        for line in lines:
            stripped_line = line.strip()
            if not stripped_line: continue

            if "PID" in line and "Name" in line: # Find header row
                header_found = True
                pid_col = line.find("PID")
                ppid_col = line.find("PPID")
                name_col = line.find("Name")
                # Basic column presence check
                if not all(c >= 0 for c in [pid_col, ppid_col, name_col]):
                     logger.warning(f"Could not reliably determine PID/PPID/Name columns in header: {line}")
                     header_found = False # Treat as unparsable if basic columns missing
                continue

            if not header_found: continue

            try:
                # Simple split parsing, assuming reasonable spacing
                parts = stripped_line.split(None, 2) # Split into PID, PPID, rest (Name + others)
                if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                    proc_info = {
                        "pid": int(parts[0]),
                        "ppid": int(parts[1]),
                        "name": parts[2].split()[0] if parts[2].split() else "" # Extract first word as name
                        # Add more parsing here if needed (User, Arch, Path) - complex/fragile
                    }
                    processes.append(proc_info)
                elif len(parts) >= 1 and parts[0].isdigit(): # Fallback if only PID found
                     logger.debug(f"Parsing process line with only PID? : {line}")
                     # processes.append({"pid": int(parts[0]), "name": " ".join(parts[1:])})
            except Exception as parse_e:
                logger.warning(f"Could not parse process line: '{line}'. Error: {parse_e}")

        status_msg = f"Processed 'ps' output (Status: {ps_result.get('status')}). Found {len(processes)} processes."
        if not header_found and raw_output:
            status_msg = "Retrieved process list but couldn't parse structured data (header not found)."
            return {"status": "partial_success", "message": status_msg, "raw_output": raw_output}

        return {"status": "success", "message": status_msg, "processes": processes, "process_count": len(processes), "raw_output": raw_output}
    else:
        logger.error(f"Failed to run 'ps' via send_session_command: {ps_result.get('message')}")
        return ps_result

@mcp.tool()
async def migrate_process(session_id: int, pid: int) -> Dict[str, Any]:
    """Migrate the Meterpreter session to another process."""
    logger.info(f"Attempting to migrate session {session_id} to process {pid}")
    session_info, error = await _verify_meterpreter_session(session_id)
    if error: return {"status": "error", "message": error}

    migrate_command = f"migrate {pid}"
    migrate_result = await send_session_command(session_id, migrate_command, timeout_seconds=60)

    if migrate_result.get("status") not in ["success", "timeout"]:
        logger.error(f"Failed to run 'migrate' command: {migrate_result.get('message')}")
        return migrate_result

    raw_output = migrate_result.get("output", "")
    logger.info(f"Migration command finished (Status: {migrate_result.get('status')}). Raw output:\n{raw_output}")

    success = "[+] Migration completed successfully" in raw_output or "[+] Successfully migrated" in raw_output
    failure = "[-] Migration failed" in raw_output or "Operation failed" in raw_output

    final_status = "success" if success else "error" if failure else "unknown"
    message = "Migration completed successfully." if success else "Migration failed." if failure else "Migration status unknown (check raw output)."
    if migrate_result.get("status") == "timeout":
        final_status = "unknown"
        message = f"Migration command timed out. Status unknown."

    return {"status": final_status, "message": message, "target_pid": pid, "raw_output": raw_output}

@mcp.tool()
async def filesystem_list(session_id: int, remote_path: str) -> Dict[str, Any]:
    """List files in a directory via a Meterpreter session."""
    logger.info(f"Listing files at '{remote_path}' for session {session_id}")

    if not isinstance(remote_path, str) or any(c in remote_path for c in ';|&`$()<>'):
        logger.error(f"Invalid characters detected in remote path: {remote_path}")
        return {"status": "error", "message": "Invalid path provided."}

    session_info, error = await _verify_meterpreter_session(session_id)
    if error: return {"status": "error", "message": error}

    # Escape double quotes in the path for the command string
    escaped_path = remote_path.replace("\"", "\\\"")
    ls_command = f'ls "{escaped_path}"'
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

            # Basic parsing assuming space separation
            parts = stripped.split(None, 4)
            if len(parts) >= 5:
                try:
                    size_val = parts[1]
                    size_int = int(size_val) if size_val.isdigit() else size_val # Keep non-int size as string
                    files.append({
                        "mode": parts[0],
                        "size": size_int,
                        "type": parts[2],
                        "last_modified": parts[3],
                        "name": parts[4]
                    })
                except Exception as parse_e: logger.warning(f"Could not parse file line '{stripped}': {parse_e}")
            # else: logger.debug(f"Skipping potential non-file line: {stripped}")

        # Determine final status message
        if "Operation failed: The system cannot find the file specified." in raw_output or "No such file or directory" in raw_output:
             return {"status": "error", "message": f"Path '{remote_path}' not found or error during listing.", "raw_output": raw_output}
        elif not files and header_found: message = f"Directory '{listing_path}' is empty or contains no parsable items."
        elif not files and not header_found:
             message = f"Command executed for '{listing_path}', but could not parse output. Check raw output."
             return {"status": "partial_success", "message": message, "path": listing_path, "raw_output": raw_output}
        elif files: message = f"Successfully listed {len(files)} files/dirs in '{listing_path}'."

        return {"status": "success", "path": listing_path, "files": files, "file_count": len(files), "message": message, "raw_output": raw_output}
    else:
        logger.error(f"Failed to run 'ls' via send_session_command: {ls_result.get('message')}")
        raw_output = ls_result.get("output", "") # Check output even on error
        if "Operation failed: The system cannot find the file specified." in raw_output or "No such file or directory" in raw_output:
            return {"status": "error", "message": f"Path '{remote_path}' not found or error during listing.", "raw_output": raw_output}
        return ls_result # Propagate other errors

@mcp.tool()
async def list_listeners() -> Dict[str, Any]:
    """List all active Metasploit jobs, categorized into handlers and others."""
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}
    logger.info("Listing active listeners/jobs")
    try:
        jobs = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
        if not isinstance(jobs, dict):
            logger.error(f"Unexpected data type for jobs list: {type(jobs)}")
            return {"status": "error", "message": f"Unexpected data type for jobs list: {type(jobs)}"}

        logger.info(f"Retrieved {len(jobs)} active jobs from MSF.")
        handlers = {}
        other_jobs = {}
        
        # Log entire jobs list for debugging
        logger.debug(f"Raw jobs list: {jobs}")
        
        for job_id, job_info in jobs.items():
            # Ensure job_id is string for consistency
            job_id_str = str(job_id)
            
            # Create a basic job data structure regardless of categorization
            job_data = {
                'job_id': job_id_str,
                'name': 'Unknown Job',
                'start_time': None
            }
            
            # Extract basic information if available 
            if isinstance(job_info, dict):
                job_data['name'] = job_info.get('name', 'Unknown Job')
                job_data['start_time'] = job_info.get('start_time')
                job_data['info'] = job_info.get('info', '')
                
                # Extract any datastore values
                datastore = job_info.get('datastore', {})
                if isinstance(datastore, dict):
                    for key, value in datastore.items():
                        job_data[key.lower()] = value
            else:
                logger.warning(f"Job {job_id_str} has non-dict job_info: {type(job_info)}")
                job_data['raw_info'] = str(job_info)
                # Still categorize non-dict jobs (don't skip)
            
            # Enhanced detection for handlers:
            # 1. Look for obvious handler indicators
            is_handler = False
            
            # Check name
            if job_data.get('name') and isinstance(job_data['name'], str):
                if 'exploit/multi/handler' in job_data['name'] or 'handler' in job_data['name'].lower():
                    is_handler = True
                    logger.debug(f"Job {job_id_str} identified as handler via name: {job_data['name']}")
            
            # Check info
            if not is_handler and job_data.get('info') and isinstance(job_data['info'], str):
                if 'exploit/multi/handler' in job_data['info'] or 'handler' in job_data['info'].lower():
                    is_handler = True
                    logger.debug(f"Job {job_id_str} identified as handler via info: {job_data['info']}")
            
            # Check raw job_info for strings if still not identified
            if not is_handler and isinstance(job_info, dict):
                # Convert the entire job_info to string and check if it contains handler indicators
                job_info_str = str(job_info).lower()
                if 'exploit/multi/handler' in job_info_str or 'handler' in job_info_str:
                    is_handler = True
                    logger.debug(f"Job {job_id_str} identified as handler via job_info string: {job_info_str[:100]}...")
            
            # 2. Check for payload-related fields that suggest a listener
            if not is_handler:
                # Handler jobs typically have payload/LHOST/LPORT settings
                if 'payload' in job_data or 'lport' in job_data or 'lhost' in job_data:
                    is_handler = True
                    logger.debug(f"Job {job_id_str} identified as handler via payload-related fields")
            
            # 3. Last-resort check: look for specific module paths in any field
            if not is_handler and isinstance(job_info, dict):
                for key, value in job_info.items():
                    if isinstance(value, str) and 'multi/handler' in value:
                        is_handler = True
                        logger.debug(f"Job {job_id_str} identified as handler via field {key}: {value}")
                        break
            
            # Categorize based on detection result
            if is_handler:
                logger.info(f"Categorized job {job_id_str} as a handler: {job_data}")
                handlers[job_id_str] = job_data
            else:
                logger.debug(f"Categorized job {job_id_str} as non-handler: {job_data}")
                other_jobs[job_id_str] = job_data

        # Fallback for uncategorized jobs:
        # If we have jobs but no handlers are found, AND the total job count
        # matches what we'd expect for handlers (e.g., when listening for connections)
        # add them to a separate section in the response
        uncategorized = {}
        if len(handlers) == 0 and len(jobs) > 0:
            logger.warning(f"No jobs categorized as handlers despite having {len(jobs)} total jobs. "
                          "Jobs might be using unexpected formats or fields.")
            for job_id, job_info in jobs.items():
                job_id_str = str(job_id)
                # Add raw job info for diagnostic purposes
                if job_id_str not in other_jobs:
                    if isinstance(job_info, dict):
                        uncategorized[job_id_str] = {
                            'job_id': job_id_str,
                            'name': job_info.get('name', 'Unknown Job'),
                            'raw_info': str(job_info)
                        }
                    else:
                        uncategorized[job_id_str] = {
                            'job_id': job_id_str,
                            'name': 'Unknown',
                            'raw_info': str(job_info)
                        }

        total_listed = len(handlers) + len(other_jobs)
        total_reported = len(jobs)
        if total_listed != total_reported:
             logger.warning(f"Job count mismatch: Listed {total_listed} (H:{len(handlers)}, O:{len(other_jobs)}), Reported by MSF: {total_reported}")

        response = {
            "status": "success",
            "handlers": handlers,
            "other_jobs": other_jobs,
            "handler_count": len(handlers),
            "other_job_count": len(other_jobs),
            "total_job_count": total_reported # Report count from MSF directly
        }
        
        # Include uncategorized jobs if we have any
        if uncategorized:
            response["uncategorized_jobs"] = uncategorized
            response["uncategorized_count"] = len(uncategorized)
            logger.warning(f"Including {len(uncategorized)} uncategorized jobs in response")
            
        return response
        
    except MsfRpcError as e:
        logger.error(f"Error listing jobs/handlers: {e}")
        return {"status": "error", "message": f"Error listing jobs: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error listing jobs/handlers.")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}


# --- Rewritten start_listener using payload object ---
@mcp.tool()
async def start_listener(
    payload_type: str,
    lhost: str,
    lport: int,
    additional_options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Start a new Metasploit handler (exploit/multi/handler) using the
    recommended payload object method. Always runs as a job.

    Args:
        payload_type: The payload to handle (e.g., 'windows/meterpreter/reverse_tcp').
        lhost: Listener host address.
        lport: Listener port.
        additional_options: Optional dict of *payload* options (e.g., LURI for HTTP).

    Returns:
        Dictionary with handler status (job_id) or error details.
    """
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    logger.info(f"Starting listener for {payload_type} on {lhost}:{lport} with options {additional_options}")
    try:
        if not all([isinstance(payload_type, str), isinstance(lhost, str), isinstance(lport, int)]):
            return {"status": "error", "message": "Invalid input types for payload, lhost, or lport."}
        if not (1 <= lport <= 65535):
            return {"status": "error", "message": "Invalid LPORT."}

        # FIXED: Use the approach from run_exploit which works for multi/handler
        module_name = "exploit/multi/handler"
        base_module_name = module_name.replace('exploit/', '', 1)
        
        # Create handler module
        module_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('exploit', base_module_name))
        logger.debug(f"Retrieved handler module object")
        
        # Set non-payload specific handler options
        await asyncio.to_thread(lambda: module_obj.__setitem__('ExitOnSession', False))
        
        # Prepare the payload options
        payload_options = additional_options or {}
        payload_options['LHOST'] = lhost
        payload_options['LPORT'] = lport
        
        # Create and configure payload object
        logger.debug(f"Preparing payload object '{payload_type}' with options")
        payload_obj = await asyncio.to_thread(lambda: _msf_client_instance.modules.use('payload', payload_type))
        
        # Set payload options
        for k, v in payload_options.items():
            if isinstance(v, str):
                if v.isdigit(): v = int(v)
                elif v.lower() in ('true', 'false'): v = v.lower() == 'true'
            await asyncio.to_thread(lambda key=k, value=v: payload_obj.__setitem__(key, value))
            logger.debug(f"Set payload option {k}={v}")
                
        # Execute handler with payload
        logger.info(f"Executing multi/handler module with payload object")
        exec_result = await asyncio.to_thread(lambda: module_obj.execute(payload=payload_obj))
        logger.info(f"Handler execution result: {exec_result}")
        
        # Process result
        if isinstance(exec_result, dict) and 'job_id' in exec_result:
            job_id = exec_result.get('job_id')
            uuid = exec_result.get('uuid')
            await asyncio.sleep(0.5) # Give job time to appear
            
            # Verify job exists
            jobs_list = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
            if str(job_id) in jobs_list:
                logger.info(f"Listener started successfully as job {job_id}.")
                return {
                    "status": "success", 
                    "message": f"Listener started as job {job_id}", 
                    "job_id": job_id, 
                    "uuid": uuid, 
                    "payload": payload_type, 
                    "lhost": lhost, 
                    "lport": lport
                }
            else:
                logger.warning(f"Handler execution reported job ID {job_id}, but job not found in list immediately.")
                return {
                    "status": "warning", 
                    "message": f"Listener job {job_id} reported but not immediately found. It might still be starting.", 
                    "job_id": job_id, 
                    "uuid": uuid
                }
        else:
            # Check for specific error messages
            error_message = f"Failed to start listener. Result: {exec_result}"
            if isinstance(exec_result, dict):
                if 'error' in exec_result and exec_result['error']:
                     error_message = f"Failed to start listener: {exec_result.get('error_message', exec_result.get('error_string', 'Unknown error'))}"
                elif 'error_message' in exec_result:
                     error_message = f"Failed to start listener: {exec_result['error_message']}"
            logger.error(error_message)
            return {"status": "error", "message": error_message}

    except MsfRpcError as e:
        if "Invalid Payload" in str(e):
             logger.error(f"Invalid payload type specified: {payload_type}")
             return {"status": "error", "message": f"Invalid payload type: {payload_type}"}
        logger.error(f"MsfRpcError starting listener: {e}")
        return {"status": "error", "message": f"Error starting listener: {str(e)}"}
    except Exception as e:
        logger.exception("Unexpected error starting listener")
        return {"status": "error", "message": f"Unexpected error starting listener: {str(e)}"}


# --- Fixed stop_job handling string return ---
@mcp.tool()
async def stop_job(job_id: int) -> Dict[str, Any]:
    """
    Stop a running Metasploit job (handler or other).
    Handles string return value from jobs.stop().
    """
    global _msf_client_instance
    if _msf_client_instance is None: return {"status": "error", "message": "MSF client not initialized."}

    logger.info(f"Attempting to stop job {job_id}")
    job_id_str = str(job_id)
    job_name = "Unknown" # Default name

    try:
        # Check if job exists before trying to stop
        jobs_before = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
        if job_id_str not in jobs_before:
            logger.error(f"Job {job_id} not found, cannot stop.")
            return {"status": "error", "message": f"Job {job_id} not found."}
        
        # Try to get job name for better reporting
        if isinstance(jobs_before.get(job_id_str), dict):
            job_name = jobs_before[job_id_str].get('name', 'Unknown Job')

        # Attempt to stop the job
        logger.debug(f"Calling jobs.stop({job_id_str})")
        stop_result = await asyncio.to_thread(lambda: _msf_client_instance.jobs.stop(job_id_str))
        logger.debug(f"jobs.stop({job_id_str}) API call returned: {stop_result} (type: {type(stop_result)})")

        # Handle the result from jobs.stop()
        # In pymetasploit3, this returns a string with a success/error message
        if isinstance(stop_result, str):
            logger.info(f"jobs.stop() returned string: '{stop_result}'")
            if 'success' in stop_result.lower():
                logger.info(f"Successfully stopped job {job_id} based on return string")
                return {
                    "status": "success", 
                    "message": f"Successfully stopped job {job_id}", 
                    "job_id": job_id, 
                    "job_name": job_name,
                    "api_result": stop_result
                }
            elif 'error' in stop_result.lower() or 'invalid' in stop_result.lower() or 'failed' in stop_result.lower():
                logger.error(f"Failed to stop job {job_id} based on return string: {stop_result}")
                return {
                    "status": "error", 
                    "message": f"Failed to stop job {job_id}: {stop_result}", 
                    "job_id": job_id, 
                    "job_name": job_name,
                    "api_result": stop_result
                }

        # Verify job stopped regardless of return value
        await asyncio.sleep(1.0) # Give MSF more time to process stop
        jobs_after = await asyncio.to_thread(lambda: _msf_client_instance.jobs.list)
        job_stopped = job_id_str not in jobs_after

        # Determine success based on disappearance of job
        if job_stopped:
            logger.info(f"Successfully stopped job {job_id} ('{job_name}') - verified by job disappearance")
            return {
                "status": "success", 
                "message": f"Successfully stopped job {job_id}", 
                "job_id": job_id, 
                "job_name": job_name,
                "api_result": str(stop_result)  # Include result for consistency
            }
        else:
            # Job didn't disappear and API result wasn't clearly success
            logger.error(f"Failed to stop job {job_id}. Job still present after stop attempt.")
            return {
                "status": "error", 
                "message": f"Failed to stop job {job_id}. Job still running after stop attempt.", 
                "job_id": job_id,
                "api_result": str(stop_result)  # Ensure we convert non-string results to string
            }

    except MsfRpcError as e:
        logger.error(f"MsfRpcError stopping job {job_id}: {e}")
        return {"status": "error", "message": f"Error stopping job {job_id}: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error stopping job {job_id}.")
        return {"status": "error", "message": f"Unexpected error stopping job {job_id}: {str(e)}"}


# --- FastAPI Application Setup ---
app = FastAPI(
    title="Metasploit MCP Server",
    description="Provides Metasploit functionality via the Model Context Protocol.",
    version="1.4.0", # Incremented version for fixes
    lifespan=None # Lifespan context manager removed as not strictly needed here
)
sse = SseServerTransport("/messages/")
# Manually add the route for POST to /messages/
app.router.routes.append(Mount("/messages", app=Starlette(routes=[
    Route("/", endpoint=sse.handle_post_message, methods=["POST"])
])))


@app.get("/sse", tags=["MCP"])
async def handle_sse_connection(request: Request): # Renamed for clarity
    """Handle Server-Sent Events connection for MCP communication."""
    async with sse.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
        await mcp._mcp_server.run(read_stream, write_stream, mcp._mcp_server.create_initialization_options())

@app.get("/healthz", tags=["Health"])
async def health_check():
    """Check connectivity to the Metasploit RPC service."""
    global _msf_client_instance
    if _msf_client_instance is None:
        raise HTTPException(status_code=503, detail="Metasploit client not initialized.")
    try:
        logger.debug("Executing health check MSF call (core.version)...")
        # Use a lightweight call like core.version for health check
        version_info = await asyncio.to_thread(lambda: _msf_client_instance.core.version)
        msf_version = version_info.get('version', 'N/A') if isinstance(version_info, dict) else 'N/A'
        logger.info(f"Health check successful. MSF Version: {msf_version}")
        return {"status": "ok", "msf_version": msf_version}
    except (MsfRpcError, ConnectionError) as e:
        logger.error(f"Health check failed - MSF RPC connection error: {e}")
        raise HTTPException(status_code=503, detail=f"Metasploit Service Unavailable: {e}")
    except Exception as e:
        logger.exception("Unexpected error during health check.")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during health check: {e}")

# --- Server Startup ---
if __name__ == "__main__":
    try:
        initialize_msf_client() # Attempt connection on startup
    except (ValueError, ConnectionError, RuntimeError) as e:
        logger.critical(f"CRITICAL: Failed to initialize Metasploit client on startup: {e}. Server cannot function.")
        import sys
        sys.exit(1) # Exit if MSF connection fails at start

    import argparse
    import socket
    import sys

    # Determine if running under Claude Desktop's stdio mode
    is_claude_stdio = not sys.stdin.isatty() if hasattr(sys.stdin, 'isatty') else False

    if is_claude_stdio:
        logger.info("Detected non-interactive stdin. Assuming Claude Desktop launch. Using stdio transport.")
        # Run MCP server over stdio
        try:
            # Note: mcp.run is synchronous, might block async tasks if not careful
            # Consider running FastAPI/uvicorn in a separate thread/process if needed
            # alongside stdio transport in more complex scenarios.
            mcp.run(transport="stdio")
        except Exception as e:
             logger.exception("Error during MCP stdio run loop.")
    else:
        logger.info("Detected interactive terminal. Starting HTTP server.")
        # --- HTTP Server Setup ---
        def find_available_port(start_port, host='0.0.0.0', max_attempts=10):
            for port in range(start_port, start_port + max_attempts):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    try:
                        s.bind((host, port))
                        logger.debug(f"Port {port} on {host} is available.")
                        return port
                    except socket.error as e:
                        logger.debug(f"Port {port} on {host} is in use ({e}), trying next.")
                        continue
            logger.warning(f"Could not find available port in range {start_port}-{start_port+max_attempts-1} on {host}. Using default {start_port}.")
            return start_port

        parser = argparse.ArgumentParser(description='Run Improved Metasploit MCP Server (HTTP Mode)')
        parser.add_argument('--host', default='127.0.0.1', help='Host to bind the HTTP server to (default: 127.0.0.1)')
        parser.add_argument('--port', type=int, default=None, help='Port to listen on (default: find available from 8085)')
        parser.add_argument('--reload', action='store_true', help='Enable auto-reload (for development)')
        parser.add_argument('--find-port', action='store_true', help='Force finding an available port starting from --port or 8085')
        args = parser.parse_args()

        selected_port = args.port
        if selected_port is None or args.find_port:
            start_port = selected_port if selected_port is not None else 8085
            selected_port = find_available_port(start_port, host=args.host)

        logger.info(f"Starting Uvicorn HTTP server on http://{args.host}:{selected_port}")
        logger.info(f"Auto-reload: {'Enabled' if args.reload else 'Disabled'}")
        logger.info("API Docs available at http://{args.host}:{selected_port}/docs")

        uvicorn.run(
            "__main__:app", # Point to the app object in the current file
            host=args.host,
            port=selected_port,
            reload=args.reload,
            log_level="info" # Use Uvicorn's logging for server events
        )