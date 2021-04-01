//
//  document-manager.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as VSCode from 'vscode';
import APIClient from './api/client';
import BaseProvider from './views/base-provider';
import { HooksProvider } from './views/hooks';
import { ProceduresProvider } from './views/procs';
import { StringsProvider } from './views/strings';

type AnyProvider = BaseProvider<any>;

export default class DocumentManager implements VSCode.TextDocumentContentProvider {
    static shared = new DocumentManager();
    
    clients: APIClient[] = [];
    activeClient: APIClient | undefined;
    
    // hooksProvider = new HooksProvider();
    procsProvider = new ProceduresProvider();
    stringsProvider = new StringsProvider();
    
    private get allProviders(): AnyProvider[] {
        return [
            /* this.hooksProvider, */ this.procsProvider, this.stringsProvider
        ];
    }
    
    registerViews() {
        // vscode.window.registerTreeDataProvider('hooks', this.hooksProvider);
        VSCode.window.registerTreeDataProvider('procs', this.procsProvider);
        VSCode.window.registerTreeDataProvider('strings', this.stringsProvider);
    }
    
    registerDocumentProviders(context: VSCode.ExtensionContext) {
        // Register a content provider for the hopper scheme
        context.subscriptions.push(VSCode.workspace.registerTextDocumentContentProvider('hopper', this));
    }
    
    // Private //
    
    private promptToStartNewClient() {
        
    }
    
    private activateClient(client: APIClient) {
        for (const provider of this.allProviders) {
            provider.client = client;
        }
    }
    
    // TextDocumentContentProvider //
    
    // Emitter and its event
    onDidChangeEmitter = new VSCode.EventEmitter<VSCode.Uri>();
    onDidChange = this.onDidChangeEmitter.event;

    provideTextDocumentContent(uri: VSCode.Uri): VSCode.ProviderResult<string> {
        const parts = uri.path.split('/');
        const segment = parts[0];
        const address = parseInt(parts[1]);
        return this.activeClient?.decompileProcedure(/* segment, */ address);
    }
}
