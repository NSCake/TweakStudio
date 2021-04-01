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
import HopperBootstrap from './bootstrap-hopper';
import DocumentManager from './document-manager';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    HopperBootstrap.extensionPath = context.extensionPath;
	
	DocumentManager.shared.registerViews();
	DocumentManager.shared.registerDocumentProviders(context);

	// Register a command that opens a Hopper document
	context.subscriptions.push(vscode.commands.registerCommand('hopper.open', async (path: string) => {
        const uri = vscode.Uri.parse('hopper:' + path);
        const doc = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(doc, { preview: false });
	}));
}
