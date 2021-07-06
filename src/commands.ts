//
//  commands.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-24
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { commands, ExtensionContext, InputBoxOptions, Uri, window, workspace } from "vscode"
import * as vscode from 'vscode';
import { EditorAction, IDAClient } from './api/client';
import HopperClient from './api/hopper';
import { IDATokenInfo } from './api/ida';
import { REDocument, Xref } from './api/model';
import HopperBootstrap from "./bootstrap/hopper";
import IdaBootstrap from "./bootstrap/ida";
import DocumentManager, { DisassemblerFamily } from "./document-manager";
import { Util } from "./util";
import { Status, Statusbar } from "./status";

function isPromise(thing: any): thing is Promise<any> {
    return !!thing.then;
}

function cmd(name: string, status?: string) {
    return function(type: Commands, propertyKey: string, descriptor: PropertyDescriptor) {
        const invocation = descriptor.value.bind(Commands.shared);
        
        if (status) {
            Commands.commandMap[name] = async (...args: any[]) => {
                // Begin showing status
                Statusbar.push(status);
                
                // Create callback to hide status
                const hide = () => {
                    Statusbar.pop(status);
                };
                
                try {
                    // Invoke method; give method responsibility to hide status
                    const maybePromise = invocation(...args, hide);
                    
                    // Hide status ourselves if it is not a promise
                    if (!isPromise(maybePromise)) {
                        hide();
                        await maybePromise;
                    }
                    
                    // Return result
                    return maybePromise;
                } catch (error) {
                    window.showErrorMessage(error.message);
                }
            };
        } else {
            Commands.commandMap[name] = (...args: any[]) => {
                try {
                    return invocation(...args);
                } catch (error) {
                    window.showErrorMessage(error.message);
                }
            };
        }
    }
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

export class Commands {
    static shared = new Commands();
    static status: vscode.StatusBarItem
    static commandMap: { [command: string]: any } = {};
    static commandStatusMap: { [command: string]: vscode.StatusBarItem } = {};
    
    public static init(context: ExtensionContext) {
        for (const [cmd, func] of Object.entries(Commands.commandMap)) {
            context.subscriptions.push(commands.registerCommand(cmd, func));
        }
        for (const [cmd, status] of Object.entries(Commands.commandMap)) {
            context.subscriptions.push(status);
        }
    }
    
    async showXrefPicker(refs: Xref[]) {
        const cmd = (await Util.pickFrom(refs)).action;
        return commands.executeCommand(cmd.command, ...cmd.arguments);
    }
    
    // Open a new document/database/binary in Hopper or IDA
    @cmd('tweakstudio.open')
    async openAnything(startIn?: string, copyTo?: string) {
        const choices = { 'IDA Pro': 'ida.open', 'Hopper': 'hopper.open' };
        const choice = await Util.pickString(Object.keys(choices));
        commands.executeCommand(choices[choice], startIn, copyTo);
    }
    @cmd('hopper.open') 
    openInHopper(startIn?: string, copyTo?: string) {
        DocumentManager.shared.promptToStartNewClient(HopperFamily, startIn, copyTo);
    }
    @cmd('ida.open') 
    openInIda(startIn?: string, copyTo?: string) {
        DocumentManager.shared.promptToStartNewClient(IDAFamily, startIn, copyTo);
    }
    @cmd('tweakstudio.sim-binary.open')
    async openBinaryFromSimulator() {
        const saveLocation = await Util.getOrPromptForPathSetting(
            'tweakstudio.simulator.binary-save-location',
            "Simulator binary save location not yet configured",
            "Choose save location"
        );
        
        try {
            const developer = await Util.getDeveloperDirectory();
            const runtimeRootComponents = [
                developer,
                'Platforms/iPhoneOS.platform',
                'Library/Developer/CoreSimulator',
                'Profiles/Runtimes/iOS.simruntime',
                'Contents/Resources/RuntimeRoot'
            ];
            commands.executeCommand(
                'tweakstudio.open',
                runtimeRootComponents.join('/'),
                saveLocation
            );
        } catch (error) {
            window.showErrorMessage(error.message);
        }
    }
    
    // Close a document
    @cmd('tweakstudio.close-document') 
    closeDocoument(doc: REDocument, hideSpinner?: () => void) {
        DocumentManager.shared.closeDocument(doc, false);
    }
    
    // For debugging, quickly open a dummy binary
    @cmd('hopper.open-test') 
    hopperOpenTest() {
        DocumentManager.shared.startNewClient(HopperBootstrap.testBinary, HopperFamily);
    }
    @cmd('ida.open-test') 
    idaOpenTest() {
        DocumentManager.shared.startNewClient(HopperBootstrap.testBinary, IDAFamily);
    }

    // Open a pseudocode document
    @cmd('hopper.view-pseudocode') 
    hopperViewPseudocode(path: string, lineno?: number) {
        // `path` already contains information about which client to use
        const port = DocumentManager.shared.activeClient.id;
        const uri = Uri.parse(path).with({ scheme: 'hopper', authority: port });
        DocumentManager.shared.showDocument(uri, lineno);
    }
    @cmd('ida.view-pseudocode') 
    idaViewPseudocode(path: string, lineno?: number) {
        // `path` already contains information about which client to use
        const port = DocumentManager.shared.activeClient.id;
        const uri = Uri.parse(path).with({ scheme: 'ida', authority: port });
        DocumentManager.shared.showDocument(uri, lineno);
    }
    
    // "Clean" a pseudocode document
    @cmd('tweakstudio.clean-pseudocode')
    cleanPseudocode() {
        DocumentManager.shared.tryCleanPseudocode();
    }
    
    // Show selrefs from selector strings
    @cmd('ida.show-selrefs', Status.selrefs) 
    async showSelrefs(address: number, hideSpinner?: () => void) {
        const refs = await DocumentManager.shared.activeClient
            .listSelrefs(address)
            .finally(hideSpinner);
            
        this.showXrefPicker(refs);
    }
    // Show xrefs from everything else
    @cmd('ida.show-xrefs', Status.xrefs) 
    async showXrefs(address: number, hideSpinner?: () => void) {
        const refs = await DocumentManager.shared.activeClient
            .listXrefs(address)
            .finally(hideSpinner);
            
        this.showXrefPicker(refs);
    }
    
    // Add a comment to a virtual document
    @cmd('ida.add-comment') 
    idaAddComment() {
        DocumentManager.tryPerformEditorAction<IDAClient>('ida', async (ida, pos) => {
            let token: IDATokenInfo = await ida.getTokenInfoAtPosition(pos);
            
            if (ida.canPerformActionOnToken(EditorAction.addComment, token.type)) {
                // Prompt for input
                const comment = await window.showInputBox({ prompt: "Add/edit a comment" });
                // Submit the comment
                console.log(`Adding comment to line ${pos.lineno}`);
                await DocumentManager.shared.activeClient.addComment(pos, comment);
                console.log('Requesting new pseudocode...');
                DocumentManager.shared.onDidChangeEmitter.fire(DocumentManager.shared.activeURI);
            }
        });
    }
    
    // Rename a variable/symbol in pseudocode
    @cmd('ida.rename') 
    idaRename() {
        DocumentManager.tryPerformEditorAction<IDAClient>('ida', async (ida, pos) => {
            let token: IDATokenInfo = await ida.getTokenInfoAtPosition(pos);
            const options: InputBoxOptions = {
                prompt: `Rename ${token.typename}`, value: token.data.name
            };
            
            // Rename symbol
            if (ida.canPerformActionOnToken(EditorAction.renameSymbol, token.type)) {
                DocumentManager.takeInput(options, async (name: string) => {
                    window.showInformationMessage("Data: " + JSON.stringify(token));
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
        });
    }
    
    // Save a document
    @cmd('tweakstudio.save-document') 
    saveDocuemnt(doc: REDocument) {
        DocumentManager.shared.saveDocument(doc, doc.defaultSaveAs);
    }
    @cmd('tweakstudio.save-as-document') 
    async saveDocumentAs(doc: REDocument) {
        const uri = await window.showSaveDialog({
            title: `Save ${doc.filename} as…`,
            defaultUri: Uri.file(doc.defaultSaveAs)
        });
        
        if (uri) {
            DocumentManager.shared.saveDocument(doc, uri.fsPath);
        }
    }
    
    // Switch to a new client
    @cmd('tweakstudio.activate-document') 
    activateDocument(doc: REDocument) {
        DocumentManager.shared.activateDocument(doc);
    }
}
