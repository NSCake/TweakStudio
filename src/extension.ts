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
import { window, workspace, commands, Uri } from 'vscode';
import HopperClient from './api/hopper';
import HopperBootstrap from './bootstrap-hopper';
import DocumentManager from './document-manager';

function reloadSettings() {
	HopperBootstrap.setHopperPath(workspace.getConfiguration('tweakstudio.hopper').get('path'));
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	// Read settings
	reloadSettings();
	let path = workspace.getConfiguration('tweakstudio.hopper').get('path');
	// Observe settings changes
	workspace.onDidChangeConfiguration(reloadSettings);
	
	// Initialize stuff
    HopperBootstrap.extensionPath = context.extensionPath;
	DocumentManager.shared.registerViews();
	DocumentManager.shared.registerDocumentProviders(context);
	
	// Register commands //
	
	// Open something in Hopper
	context.subscriptions.push(commands.registerCommand('hopper.open', async () => {
		DocumentManager.shared.promptToStartNewClient();
	}));
	
	// For debugging, quickly open a dummy binary
	context.subscriptions.push(commands.registerCommand('hopper.open-test', async () => {
		DocumentManager.shared.startNewClient(HopperBootstrap.testBinary);
	}));

	// Open a pseudocode document
	context.subscriptions.push(commands.registerCommand('hopper.view-pseudocode', async (path: string) => {
        const uri = Uri.parse('hopper:' + path);
        const doc = await workspace.openTextDocument(uri);
        await window.showTextDocument(doc, { preview: false });
	}));
}
