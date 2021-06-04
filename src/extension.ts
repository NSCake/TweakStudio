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
import IDAClient from './api/ida';
import HopperBootstrap from './bootstrap/hopper';
import IdaBootstrap from './bootstrap/ida';
import DocumentManager, { DisassemblerFamily } from './document-manager';

function reloadSettings() {
	IdaBootstrap.setIDAPath(workspace.getConfiguration('tweakstudio.ida').get('path'));
	HopperBootstrap.setHopperPath(workspace.getConfiguration('tweakstudio.hopper').get('path'));
}

const HopperFamily: DisassemblerFamily = {
	scheme: 'hopper',
	client: HopperClient,
	bootstrap: HopperBootstrap
};

const IDAFamily: DisassemblerFamily = {
	scheme: 'ida',
	client: IDAClient,
	bootstrap: IdaBootstrap
};

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	// Read settings
	reloadSettings();
	let path = workspace.getConfiguration('tweakstudio.hopper').get('path');
	// Observe settings changes
	workspace.onDidChangeConfiguration(reloadSettings);
	
	// Initialize stuff
    IdaBootstrap.extensionPath = context.extensionPath;
    HopperBootstrap.extensionPath = context.extensionPath;
	DocumentManager.shared.registerViews();
	DocumentManager.shared.registerDocumentProviders(context);
	
	// Register commands //
	
	// Open a new document/database/binary in Hopper or IDA
	context.subscriptions.push(commands.registerCommand('hopper.open', async () => {
		DocumentManager.shared.promptToStartNewClient(HopperFamily);
	}));
	context.subscriptions.push(commands.registerCommand('ida.open', async () => {
		DocumentManager.shared.promptToStartNewClient(IDAFamily);
	}));
	
	// For debugging, quickly open a dummy binary
	context.subscriptions.push(commands.registerCommand('hopper.open-test', async () => {
		DocumentManager.shared.startNewClient(HopperBootstrap.testBinary, HopperFamily);
	}));
	context.subscriptions.push(commands.registerCommand('ida.open-test', async () => {
		DocumentManager.shared.startNewClient(HopperBootstrap.testBinary, IDAFamily);
	}));

	// Open a pseudocode document
	context.subscriptions.push(commands.registerCommand('hopper.view-pseudocode', async (path: string) => {
		const uri = Uri.parse('hopper:' + path);
        const doc = await workspace.openTextDocument(uri);
        await window.showTextDocument(doc, { preview: false });
	}));
	context.subscriptions.push(commands.registerCommand('ida.view-pseudocode', async (path: string) => {
		// DocumentManager.shared.switchToClient()
		const port = DocumentManager.shared.activeClient.id;
        const uri = Uri.parse('ida:' + path).with({ query: port });
        const doc = await workspace.openTextDocument(uri);
        await window.showTextDocument(doc, { preview: false });
	}));
}

export function deactivate(context: vscode.ExtensionContext) {
	DocumentManager.shared.shutdown();
}
