//
//  bootstrap-hopper.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as VSCode from 'vscode';
import { exec } from 'child_process';
import { createServer } from 'http';

export default class HopperBootstrap {
    static extensionPath: string = "";
    static hopperPath: string = "hopper";
    
    private static get proxyScript(): string {
        return `${this.extensionPath}/hopper/proxy.py`;
    }
    
    private static get testBinary(): string {
        return `${this.extensionPath}/test/FLEXing`;
    }
    
    /** A map of database or binary paths to ports. Also includes temporary server ports. */
    private static portMap: { [path: string]: number } = {};
    /** A list of the ports currently in use */
    private static get portsInUse(): number[] {
        return Object.values(this.portMap);
    }
    
    /** A random, unused port. */
    private static randomPort(): number {
        // Random number between 49152 and 65535
        const port = Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152;
        
        // Try again if already used
        if (this.portsInUse.includes(port)) {
            return this.randomPort();
        }
        
        return port;
    }
    
    /** Map a path to the key associated with its callback server. */
    private static serverIDForPath(path: string): string {
        return `serve-${path}`;
    }
    
    /** Map a path to the port associated with its callback server. */
    private static callbackPortForPath(path): number {
        return this.portMap[this.serverIDForPath(path)];
    }
    
    private static binaryCommand(format: string, arch: string, binary: string): string {
        return `${this.hopperPath} -l ${format} ${arch} -Y '${this.proxyScript}' -e '${binary}'`;
    }
    
    /**
     * Start a new Hopper instance with the given path.
     * @param path A path to a .hop document or an executable file.
     * @return The port associated with the new Hopper instance to pull data from.
     */
    static async openFile(path: string): Promise<number> {
        return new Promise((resolve, reject) => {
            // Start the callback server before we launch Hopper
            const clientPort = this.serveNewClient(path);
            // Await the new client's ping so we can assign it a port
            clientPort.then(p => resolve(p));
            clientPort.catch(e => reject(e));
            
            // Get the port we're listening on
            const port = this.callbackPortForPath(path);
            
            // Start Hopper, wait for callback
            const command = this.binaryCommand('FAT', '--aarch64', path);
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                }
            });
            
            return clientPort;
        });
    }

    /**
     * Starts a temporary callback webserver and waits for our proxy script
     * to call back and let us know when it's ready to receive commands.
     * 
     * @param path A path to a .hop document or an executable file.
     * @return The port associated with the new Hopper instance.
     */
    static async serveNewClient(path: string): Promise<number> {
        // Create and reserve temporary server port
        const tempServerID = this.serverIDForPath(path);
        const callbackPort = this.portMap[tempServerID] = this.randomPort();
        
        return new Promise((resolve, reject) => {
            const server = createServer();

            // Start a server hosting an endpoint at the port we pass to the client
            server.on('request', (request, response) => {
                // TODO: check request endpoint, should be `tweakstudio/hopper`
                response.end();
                
                // Reserve client port, fufill port promise
                this.portMap[path] = 5; // TODO: read port
                resolve(5);
                
                // Stop the server
                server.close((error) => {
                    // Log any error
                    if (error) {
                        console.log(error);
                    }
                    
                    // Release temporary server port
                    delete this.portMap[tempServerID];
                });
            });

            // Listen for new clients on callbackPort
            server.listen(callbackPort, () => {
                console.log(`Listening for Hopper callback on port ${callbackPort}`);
            });
        });
    }
}
