//
//  extension.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-02
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

'use strict';
// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import HopperClient from './api/hopper';
import { HooksProvider } from './views/hooks';
import { ProceduresProvider } from './views/procs';
import { StringsProvider } from './views/strings';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    
    vscode.window.registerTreeDataProvider('procs', new ProceduresProvider());
    // vscode.window.registerTreeDataProvider('hooks', new HooksProvider());
    vscode.window.registerTreeDataProvider('strings', new StringsProvider());
    
    // Register a content provider for the hopper-scheme
	const myScheme = 'hopper';
	const myProvider = new class implements vscode.TextDocumentContentProvider {

		// Emitter and its event
		onDidChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
		onDidChange = this.onDidChangeEmitter.event;

		provideTextDocumentContent(uri: vscode.Uri): vscode.ProviderResult<string> {
            const parts = uri.path.split('/');
            const segment = parts[0];
            const address = parseInt(parts[1]);
			return HopperClient.shared.decompileProcedure(segment, address);
		}
	};
	context.subscriptions.push(vscode.workspace.registerTextDocumentContentProvider(myScheme, myProvider));

	// Register a command that opens a Hopper document
	context.subscriptions.push(vscode.commands.registerCommand('hopper.open', async (path: string) => {
        const uri = vscode.Uri.parse('hopper:' + path);
        const doc = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(doc, { preview: false });
	}));
}
