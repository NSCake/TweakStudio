//
//  bootstrap/ida.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { window } from 'vscode';
import { exec } from 'child_process';
import * as Express from 'express';
import * as fs from 'fs';
import { Util } from '../util';
import { Status, Statusbar } from '../status';
import { ChildProcess } from 'node:child_process';

interface IDAFlags {
    overwrite?: boolean, // Defaults to NO
    slice?: number, // undefined if not FAT
}

export default class IdaBootstrap {
    static extensionPath: string = "";
    private static idaPath: string | undefined;
    
    static async setIDAPath(path: string) {
        try {
            await fs.promises.access(path);
            this.idaPath = `${path}/Contents/MacOS/ida64`;
        } catch (error) {
            window.showErrorMessage(`IDA instance not found at '${path}'`);
        }
    }
    
    private static get proxyScript(): string {
        return `${this.extensionPath}/ida/proxy.py`;
    }
    
    static get testBinary(): string {
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
    
    private static async commandToOpenFile(path: string): Promise<string> {
        if (path.endsWith('.i64') || path.endsWith('.idb')) {
            return this.openDatabaseCommand(path);
        }
        
        // List architectures
        const archs = await Util.archsForFile(path);
        if (archs.length > 1) {
            // Case: FAT binary, must choose arch
            const choice = await Util.pickString(archs);
            return this.openBinaryCommand(path, { overwrite: true, slice: archs.indexOf(choice) });
        } else {
            // Case: non-FAT binary, do not choose arch
            return this.openBinaryCommand(path, { overwrite: true });
        }
    }
    
    private static openDatabaseCommand(db: string): string {
        
        // Make sure you check this.idaPath before calling me
        return `"${this.idaPath!}" -S"${this.proxyScript}" -A "${db}"`;
    }
    
    private static openBinaryCommand(binary: string, flags: IDAFlags): string {
        const fatSlice = flags.slice !== undefined ? `"-TFat Mach-O File, ${flags.slice!}"` : '';
        const replace = flags.overwrite ? '-c' : '';
        
        // Make sure you check this.idaPath before calling me
        return `"${this.idaPath!}" ${replace} ${fatSlice} -S"${this.proxyScript}" -A "${binary}"`;
    }
    
    /**
     * Start a new IDA instance with the given path.
     * @param path A path to a .i64 document or an executable file.
     * @return The process and port associated with the new IDA instance to pull data from.
     */
    static async openFile(path: string): Promise<[ChildProcess, number]> {
        // Generate the command first; we will run `lipo` to determine
        // the architecture choices and allow the user to choose one,
        // or abort if the file is not a Mach-O and displaly an error.
        // The error is propogated and displayed if we await this inside
        // the promise we return below. Await it here before the promise.
        const command = await this.commandToOpenFile(path);
        
        // Do we have a valid copy of IDA?
        if (!this.idaPath) {
            throw { message: 'IDA not found; ensure IDA path setting is valid' };
        }
        
        // Push status
        Statusbar.push(Status.init_ida);
        
        return new Promise(async (resolve, reject) => {
            // Start the callback server before we launch IDA
            const clientPort = this.serveNewClient(path);
            
            // Get the port we're listening on and setup env vars
            const port = this.callbackPortForPath(path).toString();
            const env = Object.create(process.env);
            env.EXT_PORT = port;
            
            // Start IDA, wait for callback
            const child = exec(command, { env: env }, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                }
            });
            
            try {
                await clientPort
                    .then(p => resolve([child, p]))
                    .finally(Statusbar.popper(Status.init_ida));
            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Starts a temporary callback webserver and waits for our proxy script
     * to call back and let us know when it's ready to receive commands.
     * 
     * @param path A path to a .hop document or an executable file.
     * @return The port associated with the new IDA instance.
     */
    static async serveNewClient(path: string): Promise<number> {
        // Create and reserve temporary server port
        const tempServerID = this.serverIDForPath(path);
        const callbackPort = this.portMap[tempServerID] = this.randomPort();
        
        return new Promise((resolve, reject) => {
            const tempApp = Express();
            tempApp.use(Express.json());
            
            // Listen for new clients on callbackPort
            const server = tempApp.listen(callbackPort, () => {
                console.log(`Listening for IDA callback on port ${callbackPort}`);
            });

            // Start a server hosting an endpoint at the port we pass to the client
            tempApp.post('/tweakstudio/ida', (request, response) => {
                if (request.body.port) {
                    // Reserve client port, fufill promise
                    this.portMap[path] = request.body.port;
                    resolve(request.body.port);
                    
                    // Release temporary server port
                    delete this.portMap[tempServerID];
                    
                    response.status(200);
                    
                    // Stop the server
                    server.close();
                    console.log(`Got response with port ${request.body.port}`);
                } else {
                    // Missing port
                    reject("Prox callback was missing port");                    
                    response.status(400);
                }
            });
        });
    }
}
