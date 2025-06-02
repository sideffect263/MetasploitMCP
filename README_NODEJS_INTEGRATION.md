# Metasploit MCP Server - Node.js Integration Guide

This guide shows how to integrate the Metasploit MCP server with your Node.js application.

## Prerequisites

1. Metasploit Framework with RPC daemon running:
   ```bash
   msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
   ```

2. Metasploit MCP server running:
   ```bash
   python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
   ```

3. Node.js project with required dependencies:
   ```json
   {
     "dependencies": {
       "@modelcontextprotocol/sdk": "^0.5.0",
       "eventsource": "^2.0.2"
     }
   }
   ```

## Basic Usage

```javascript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import EventSource from 'eventsource';

// Required for Node.js environment
global.EventSource = EventSource;

async function connectToMetasploit() {
    // Create SSE transport
    const transport = new SSEClientTransport(
        new URL('http://localhost:8085/sse')
    );

    // Create MCP client
    const client = new Client({
        name: 'my-nodejs-app',
        version: '1.0.0'
    }, {
        capabilities: {}
    });

    // Connect to server
    await client.connect(transport);
    console.log('Connected to Metasploit MCP server');

    return client;
}
```

## Available Tools

The MCP server provides these tools:

- `list_exploits` - Search for exploit modules
- `list_payloads` - Search for payload modules
- `generate_payload` - Generate payload files
- `run_exploit` - Execute exploit modules
- `run_auxiliary_module` - Execute auxiliary modules
- `run_post_module` - Execute post-exploitation modules
- `list_active_sessions` - List current sessions
- `send_session_command` - Execute commands in sessions
- `list_listeners` - List active handlers/jobs
- `start_listener` - Start a new handler
- `stop_job` - Stop a running job
- `terminate_session` - End a session

## Example: Complete Client Class

```javascript
class MetasploitClient {
    constructor(url = 'http://localhost:8085') {
        this.url = url;
        this.client = null;
        this.transport = null;
    }

    async connect() {
        this.transport = new SSEClientTransport(
            new URL(`${this.url}/sse`)
        );

        this.client = new Client({
            name: 'metasploit-nodejs-client',
            version: '1.0.0'
        }, {
            capabilities: {}
        });

        await this.client.connect(this.transport);
    }

    async callTool(toolName, args) {
        const result = await this.client.callTool(toolName, args);
        
        // Parse the response
        if (result.content && result.content.length > 0) {
            const content = result.content[0];
            if (content.type === 'text' && content.text) {
                try {
                    return JSON.parse(content.text);
                } catch {
                    return content.text;
                }
            }
            return content;
        }
        return result;
    }

    async listExploits(searchTerm = '') {
        return this.callTool('list_exploits', { 
            search_term: searchTerm 
        });
    }

    async startListener(payloadType, lhost, lport) {
        return this.callTool('start_listener', {
            payload_type: payloadType,
            lhost: lhost,
            lport: lport
        });
    }

    async disconnect() {
        if (this.client) {
            await this.client.close();
        }
    }
}
```

## Usage Examples

### Search for Exploits
```javascript
const client = new MetasploitClient();
await client.connect();

const exploits = await client.listExploits('ms17_010');
console.log('Found exploits:', exploits);

await client.disconnect();
```

### Start a Listener
```javascript
const result = await client.startListener(
    'windows/meterpreter/reverse_tcp',
    '0.0.0.0',
    4444
);
console.log('Listener started:', result);
```

### List Active Sessions
```javascript
const sessions = await client.callTool('list_active_sessions', {});
console.log('Active sessions:', sessions);
```

### Run Commands in a Session
```javascript
const result = await client.callTool('send_session_command', {
    session_id: 1,
    command: 'sysinfo',
    timeout_seconds: 30
});
console.log('Command output:', result.output);
```

## Important Notes

1. **Error Handling**: Always wrap tool calls in try-catch blocks
2. **Security**: This gives full access to Metasploit - use carefully
3. **Async Operations**: All operations are asynchronous
4. **Session Management**: Always disconnect when done

## Troubleshooting

If you get "Could not parse message" errors:
- Make sure you're using the official MCP SDK
- Ensure EventSource is properly polyfilled
- Check that the message format matches the JSON-RPC spec

For connection issues:
- Verify the MCP server is running on the correct port
- Check firewall settings
- Ensure the Metasploit RPC daemon is accessible 