//
//  extension.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-02
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

'use strict';
import * as vscode from 'vscode';
import { workspace, commands } from 'vscode';
import HopperBootstrap from './bootstrap/hopper';
import IdaBootstrap from './bootstrap/ida';
import { Commands } from './commands';
import DocumentManager from './document-manager';
import { Statusbar } from './status';

function reloadSettings() {
    IdaBootstrap.setIDAPath(workspace.getConfiguration('tweakstudio.ida').get('path'));
    HopperBootstrap.setHopperPath(workspace.getConfiguration('tweakstudio.hopper').get('path'));
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    // Read settings
    reloadSettings();
    // Observe settings changes
    workspace.onDidChangeConfiguration(reloadSettings);
    
    // Initialize stuff
    IdaBootstrap.extensionPath = context.extensionPath;
    HopperBootstrap.extensionPath = context.extensionPath;
    DocumentManager.shared.registerViews();
    DocumentManager.shared.registerDocumentProviders(context);
    
    // Register commands //
    Commands.init(context);
    // GC status bar //
    Statusbar.init(context);
}

export function deactivate(context: vscode.ExtensionContext) {
    DocumentManager.shared.shutdown();
}
