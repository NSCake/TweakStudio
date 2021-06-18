//
//  extension.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-02
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

'use strict';
import * as vscode from 'vscode';
import { window, workspace, commands, Uri } from 'vscode';
import { EditorAction, IDAClient } from './api/client';
import HopperClient from './api/hopper';
import IDATokenType, { IDATokenInfo } from './api/ida';
import { Procedure, Xref } from './api/model';
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

function registerCommand(cmd: string, ctx: vscode.ExtensionContext, cb) {
    ctx.subscriptions.push(commands.registerCommand(cmd, cb));
};

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
    
    // Open a new document/database/binary in Hopper or IDA
    registerCommand('hopper.open', context, async () => {
        DocumentManager.shared.promptToStartNewClient(HopperFamily);
    });
    registerCommand('ida.open', context, async () => {
        DocumentManager.shared.promptToStartNewClient(IDAFamily);
    });
    
    // For debugging, quickly open a dummy binary
    registerCommand('hopper.open-test', context, async () => {
        DocumentManager.shared.startNewClient(HopperBootstrap.testBinary, HopperFamily);
    });
    registerCommand('ida.open-test', context, async () => {
        DocumentManager.shared.startNewClient(HopperBootstrap.testBinary, IDAFamily);
    });

    // Open a pseudocode document
    registerCommand('hopper.view-pseudocode', context, async (path: string, lineno?: number) => {
        DocumentManager.shared.showDocument(Uri.parse('hopper:' + path), lineno);
    });
    registerCommand('ida.view-pseudocode', context, async (path: string, lineno?: number) => {
        // DocumentManager.shared.switchToClient()
        const port = DocumentManager.shared.activeClient.id;
        const uri = Uri.parse('ida:' + path).with({ query: port });
        DocumentManager.shared.showDocument(uri, lineno);
    });
    
    // "Clean" a pseudocode document
    registerCommand('tweakstudio.clean-pseudocode', context, () => {
        DocumentManager.shared.tryCleanPseudocode();
    });
    
    function showXrefPicker(refs: Xref[]) {
        const quickPick = window.createQuickPick();
        quickPick.items = refs;
        quickPick.onDidChangeSelection((selection: Xref[]) => {
            const cmd = selection[0].action;
            commands.executeCommand(cmd.command, ...cmd.arguments);
        });
        quickPick.onDidHide(() => quickPick.dispose());
        quickPick.show();
    }
    
    // Show selrefs from selector strings
    registerCommand('ida.show-selrefs', context, async (address: number) => {
        const refs = await DocumentManager.shared.activeClient.listSelrefs(address);
        showXrefPicker(refs);
    });
    // Show xrefs from everything else
    registerCommand('ida.show-xrefs', context, async (address: number) => {
        const refs = await DocumentManager.shared.activeClient.listXrefs(address);
        showXrefPicker(refs);
    });
    
    // Add a comment to a virtual document
    registerCommand('ida.add-comment', context, async () => {
        DocumentManager.tryPerformEditorAction<IDAClient>('ida', async (ida, pos) => {
            let token: IDATokenInfo = await ida.getTokenInfoAtPosition(pos);
            
            if (ida.canPerformActionOnToken(EditorAction.addComment, token.type)) {
                window.showInformationMessage("Data: " + JSON.stringify(token.data));
                return;
                // Prompt for input
                const comment = await window.showInputBox({ prompt: "Add/edit a comment" });
                // Submit the comment
                DocumentManager.shared.activeClient.addComment(pos, comment);
                // TODO: refresh document?
            }
        });
    });
    
    // Rename a variable/symbol in pseudocode
    registerCommand('ida.rename', context, async () => {
        DocumentManager.tryPerformEditorAction<IDAClient>('ida', async (ida, pos) => {
            let token: IDATokenInfo = await ida.getTokenInfoAtPosition(pos);
            const options: vscode.InputBoxOptions = {
                prompt: `Rename ${token.typename}`, value: token.data.name
            };
            
            // Rename symbol
            if (ida.canPerformActionOnToken(EditorAction.renameSymbol, token.type)) {
                DocumentManager.takeInput(options, async (name: string) => {
                    window.showInformationMessage("Data: " + JSON.stringify(token));
                    return;
                });
            }
            // Rename variable
            else if (ida.canPerformActionOnToken(EditorAction.renameVar, token.type)) {
                DocumentManager.takeInput(options, async (name: string) => {
                    console.log(`Renaming var ${token.data.name} @${token.data.lvar} to ${name}`);
                    await DocumentManager.shared.activeClient.ida.renameLvar(pos.funcAddr, token.data.lvar, name);
                    console.log('Requesting new pseudocode...');
                    DocumentManager.shared.onDidChangeEmitter.fire(DocumentManager.shared.activeURI);
                });
            }
        })
    });
}

export function deactivate(context: vscode.ExtensionContext) {
    DocumentManager.shared.shutdown();
}
