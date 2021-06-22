//
//  document-manager.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as VSCode from 'vscode';
import { InputBoxOptions, window, workspace } from 'vscode';
import APIClient, { CursorPosition, Disassembler } from './api/client';
import HopperClient from './api/hopper';
import { Procedure, REDocument } from './api/model';
import DisassemblerBootstrap from './bootstrap/bootstrap';
import HopperBootstrap from './bootstrap/hopper';
import CleanIDAPseudocode from './psc/ida-psc-cleaner';
import BaseProvider from './views/base-provider';
import { HooksProvider } from './views/hooks';
import { OpenDocumentsProvider } from './views/open-documents';
import { ProceduresProvider } from './views/procs';
import { SelectorsProvider } from './views/selectors';
import { StringsProvider } from './views/strings';

type AnyProvider = BaseProvider<any>;

export interface DisassemblerFamily {
    scheme: Disassembler;
    client: new(scheme: string, port: number, file: string) => APIClient;
    bootstrap: DisassemblerBootstrap;
}

export default class DocumentManager implements VSCode.TextDocumentContentProvider {    
    static shared = new DocumentManager();
    
    private clients: APIClient[] = [];
    private _activeClient: APIClient | undefined;
    
    public get activeClient(): APIClient | undefined {
        return this._activeClient;
    }
    
    public get allDocuments(): REDocument[] {
        return this.clients.map(c => c.document);
    }
    
    // hooksProvider = new HooksProvider();
    private docsProvider = new OpenDocumentsProvider();
    private procsProvider = new ProceduresProvider();
    private selectorsProvider = new SelectorsProvider();
    private stringsProvider = new StringsProvider();
    
    private get allProviders(): AnyProvider[] {
        return [
            /* this.hooksProvider, */
            this.docsProvider,
            this.procsProvider,
            this.selectorsProvider,
            this.stringsProvider
        ];
    }
    
    private cleanNext: VSCode.Uri | undefined;
    
    // Initialization //
    
    public registerViews() {
        // window.registerTreeDataProvider('hooks', this.hooksProvider);
        window.registerTreeDataProvider('open-documents', this.docsProvider);
        window.registerTreeDataProvider('procs', this.procsProvider);
        window.registerTreeDataProvider('selectors', this.selectorsProvider);
        window.registerTreeDataProvider('strings', this.stringsProvider);
    }
    
    public registerDocumentProviders(context: VSCode.ExtensionContext) {
        // Register a content provider for the two schemes
        context.subscriptions.push(VSCode.workspace.registerTextDocumentContentProvider('hopper', this));
        context.subscriptions.push(VSCode.workspace.registerTextDocumentContentProvider('ida', this));
    }
    
    // Documents //
    
    public async showDocument(uri: VSCode.Uri, lineno?: number) {
        const doc = await this.documentforURI(uri);
        await window.showTextDocument(doc, { preview: true });
        
        // Scroll to the given line, if given a line
        if (lineno !== undefined) {
            const line = doc.lineAt(new VSCode.Position(lineno-1, 0)).range;
            window.activeTextEditor.revealRange(line, VSCode.TextEditorRevealType.InCenterIfOutsideViewport);
        }
    }
    
    private async documentforURI(uri: VSCode.Uri): Promise<VSCode.TextDocument> {
        // Check if document is open first
        for (const editor of window.visibleTextEditors) {
            if (editor.document.uri.toString() == uri.toString()) {
                return editor.document;
            }
        }
        
        return workspace.openTextDocument(uri);
    }
    
    // Misc //
    
    public get activeURI(): VSCode.Uri | undefined {
        return this.activeEditor?.document.uri;
    }
    
    public get activeEditor(): VSCode.TextEditor | undefined {
        return DocumentManager.activeEditor(this.activeClient.scheme);
    }
    
    public static activeEditor(scheme: string): VSCode.TextEditor | undefined {
        const editor = VSCode.window.activeTextEditor;
        return editor.document.uri.scheme == scheme ? editor : undefined;
    }
    
    /**
     * Executes the callback if the current editor's current scheme matches the given one,
     * and if the selection is just a single position and not a real selection.
     */
    public static tryPerformEditorAction<T extends APIClient>(scheme: string, callback: (client: T, pos: CursorPosition) => void) {
        const editor = this.activeEditor(scheme);
        const allowed = editor // Must have active editor with same scheme
            && editor.selection.isSingleLine; // Can only perform actions one line at a time
        
        if (allowed) {
            const col = editor.selection.start.character;
            const line = editor.selection.start.line;
            const uri = editor.document.uri;
            const funcAddr = Procedure.parseURI(uri).addr;
            
            const client: T = DocumentManager.shared.activeClient[scheme];
            if (client) {
                callback(client, { funcAddr: funcAddr, lineno: line, col: col });
            }
        }
    }
    
    public static async takeInput(options: InputBoxOptions, callback: (input: string) => void) {
        const input = await window.showInputBox(options);
        if (input?.length) {
            callback(input);
        }
    }
    
    public tryCleanPseudocode() {
        const doc = this.activeEditor.document
        this.cleanNext = doc.uri;
        this.onDidChangeEmitter.fire(doc.uri);
    }
    
    // Client management //
    
    public async promptToStartNewClient(family: DisassemblerFamily) {
        // Show file picker
        const selection = await VSCode.window.showOpenDialog({ 'canSelectMany': false });
        if (selection) {
            await this.startNewClient(selection[0].path, family);
        }
    }
    
    public async startNewClient(path: string, family: DisassemblerFamily) {
        try {
            // Activate our view
            VSCode.commands.executeCommand('workbench.view.extension.tweakstudio');

            // Bootstrap selected file in Hopper
            const port = await family.bootstrap.openFile(path);
            const client = new family.client(family.scheme, port, path);
            this.addClient(client, true);
        } catch (error) {
            window.showErrorMessage(error.message);
        }
    }
    
    private addClient(client: APIClient, activate: boolean) {
        this.clients.push(client);
        // Update documents list in sidebar
        this.docsProvider.refresh();
        
        if (activate) {
            this.switchToClient(client);            
        }
    }
    
    public async closeDocument(doc: REDocument, save: boolean): Promise<void> {
        // Search for the client associated with this document
        for (const client of this.clients.filter(c => c.scheme == doc.family)) {
            if (doc.path == client.filepath) {
                
                // Remove the document prior to closing
                this.clients = this.clients.filter(c => c !== client);
                
                // If it was the active client, then switch to the first one
                if (client == this.activeClient && this.clients.length) {
                    this.switchToClient(this.clients[0]);
                } else if (!this.clients.length) {
                    this.switchToClient(undefined);
                }
                
                // Actually close the client
                return client.shutdown(save);
            }
        }
    }
    
    public switchToClient(client: APIClient | undefined) {
        this._activeClient = client;

        for (const provider of this.allProviders) {
            provider.client = client;
        }
    }
    
    private clientWithID(id: string): APIClient | undefined {
        return this.clients.filter(c => c.id == id)[0];
    }
    
    public shutdown() {
        this.clients.forEach(c => c.shutdown());
        this._activeClient = undefined;
        this.clients = [];
    }
    
    // TextDocumentContentProvider //
    
    // Emitter and its event
    onDidChangeEmitter = new VSCode.EventEmitter<VSCode.Uri>();
    onDidChange = this.onDidChangeEmitter.event;

    async provideTextDocumentContent(uri: VSCode.Uri): Promise<string> {
        const scheme = uri.scheme;
        const parts = uri.path.split('/');
        // const segment = parts[0];
        const address = parseInt(parts[1]);
        const id = uri.query;
        const code = await this.clientWithID(id)?.decompileProcedure(/* segment, */ address);
        console.log(`Did decompile ${scheme} function at ${address}`)
        
        if (this.cleanNext?.toString() == uri.toString()) {
            this.cleanNext = undefined;
            switch (scheme) {
                case 'ida': return CleanIDAPseudocode(code);
            }
            
            console.log('Did clean pseudocode');
        }
        
        return code;
    }
}
