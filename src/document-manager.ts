//
//  document-manager.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as VSCode from 'vscode';
import { window } from 'vscode';
import APIClient from './api/client';
import HopperClient from './api/hopper';
import DisassemblerBootstrap from './bootstrap/bootstrap';
import HopperBootstrap from './bootstrap/hopper';
import BaseProvider from './views/base-provider';
import { HooksProvider } from './views/hooks';
import { ProceduresProvider } from './views/procs';
import { SelectorsProvider } from './views/selectors';
import { StringsProvider } from './views/strings';

type AnyProvider = BaseProvider<any>;

export interface DisassemblerFamily {
    scheme: string;
    client: typeof APIClient;
    bootstrap: DisassemblerBootstrap;
}

export default class DocumentManager implements VSCode.TextDocumentContentProvider {
    static shared = new DocumentManager();
    
    clients: APIClient[] = [];
    activeClient: APIClient | undefined;
    
    // hooksProvider = new HooksProvider();
    procsProvider = new ProceduresProvider();
    selectorsProvider = new SelectorsProvider();
    stringsProvider = new StringsProvider();
    
    private get allProviders(): AnyProvider[] {
        return [
            /* this.hooksProvider, */ this.procsProvider, this.selectorsProvider, this.stringsProvider
        ];
    }
    
    registerViews() {
        // window.registerTreeDataProvider('hooks', this.hooksProvider);
        window.registerTreeDataProvider('procs', this.procsProvider);
        window.registerTreeDataProvider('selectors', this.selectorsProvider);
        window.registerTreeDataProvider('strings', this.stringsProvider);
    }
    
    registerDocumentProviders(context: VSCode.ExtensionContext) {
        // Register a content provider for the two schemes
        context.subscriptions.push(VSCode.workspace.registerTextDocumentContentProvider('hopper', this));
        context.subscriptions.push(VSCode.workspace.registerTextDocumentContentProvider('ida', this));
    }
    
    // Private //
    
    async promptToStartNewClient(family: DisassemblerFamily) {
        // Show file picker
        const selection = await VSCode.window.showOpenDialog({ 'canSelectMany': false });
        if (selection) {
            await this.startNewClient(selection[0].path, family);
		}
    }
    
    async startNewClient(path: string, family: DisassemblerFamily) {
        try {
            // Activate our view
            VSCode.commands.executeCommand('workbench.view.extension.tweakstudio');

            // Bootstrap selected file in Hopper
            const port = await family.bootstrap.openFile(path);
            const client = new family.client(family.scheme, port);
            this.addClient(client, true);
        } catch (error) {
            window.showErrorMessage(error.message);
        }
    }
    
    addClient(client: APIClient, activate: boolean) {
        this.clients.push(client);
        
        if (activate) {
            this.switchToClient(client);            
        }
    }
    
    switchToClient(client: APIClient) {
        this.activeClient = client;

        for (const provider of this.allProviders) {
            provider.client = client;
        }
    }
    
    clientWithID(id: string): APIClient | undefined {
        return this.clients.filter(c => c.id == id)[0];
    }
    
    shutdown() {
        this.clients.forEach(c => c.shutdown());
        this.activeClient = undefined;
        this.clients = [];
    }
    
    // TextDocumentContentProvider //
    
    // Emitter and its event
    onDidChangeEmitter = new VSCode.EventEmitter<VSCode.Uri>();
    onDidChange = this.onDidChangeEmitter.event;

    provideTextDocumentContent(uri: VSCode.Uri): VSCode.ProviderResult<string> {
        const parts = uri.path.split('/');
        // const segment = parts[0];
        const address = parseInt(parts[1]);
        const id = uri.query;
        return this.clientWithID(id)?.decompileProcedure(/* segment, */ address);
    }
}
