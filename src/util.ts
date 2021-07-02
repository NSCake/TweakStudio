//
//  util.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-27
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { exec } from "child_process";
import { QuickPickItem, Uri, window, workspace } from "vscode";

export class Util {
    
    static isString(value: unknown): value is string {
        return typeof value == 'string';
    }
    
    static valueOrReject<T>(value: T | T[], first: boolean = false): T | Promise<T> {
        if (value) {
            if (first && Array.isArray(value) && value.length) {
                return value[0];
            }
            
            return value as T;
        }
        
        return Promise.reject();
    }
    
    /**
     * Returns a list of architecture strings (in slice order) or rejects if not a Mach-O.
     * One architecture means it is not a FAT binary.
     */
    static async archsForFile(path: string): Promise<string[]> {
        await this.assertBinaryNotEncrypted(path);
        
        return new Promise((resolve, reject) => {
            exec(`lipo -archs '${path}'`, (error, stdout, stderr) => {
                if (error) {
                    // Attempt to extract the lipo error message directly, first
                    const msg = error.message.split('lipo: ')[1].replace('\n', '');
                    error.message = msg ?? error.message;
                    reject(error);
                } else {
                    resolve(stdout.replace('\n', '').split(' '));
                }
            });
        });
    }
    
    static assertBinaryNotEncrypted(path: string): Promise<void> {
        return new Promise((resolve, reject) => {
            // We use `cat` to hide grep failing if no match found, while
            // allowing errors from `otool` missing or something
            exec(`otool -l '${path}' | grep cryptid | cat`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else if (stdout.includes('cryptid 1')) {
                    reject({ message: 'Binary is FairPlay encrypted' });
                } else {
                    resolve();
                }
            });
        });
    }
    
    static getDeveloperDirectory(): Promise<string> {
        return new Promise((resolve, reject) => {
            exec(`xcode-select -p`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout.replace('\n', ''));
                }
            });
        });
    }
    
    /** Returns one choice, rejects if nothing selected */
    static pickFrom<T extends QuickPickItem>(choices: T[]): Promise<T> {
        return new Promise((resolve, reject) => {
            const quickPick = window.createQuickPick();
            quickPick.canSelectMany = false;
            quickPick.items = choices;
            
            quickPick.onDidChangeSelection((selection: any[]) => {
                if (selection.length) {
                    resolve(selection[0]);
                } else {
                    reject();
                }
            });
            
            quickPick.onDidHide(() => quickPick.dispose());
            quickPick.show();
        });
    }
    
    /** Returns one choice, rejects if nothing selected */
    static async pickString(choices: string[]): Promise<string> {
        const choice = await window.showQuickPick(choices, { canPickMany: false });
        return this.valueOrReject(choice);
    }
    
    /** Returns one folder selection, rejects if nothing selected */
    static async selectSingleFolder(): Promise<Uri> {
        const selection = await window.showOpenDialog({
            canSelectMany: false,
            canSelectFiles: false,
            canSelectFolders: true,
        });
        
        return this.valueOrReject(selection, true);
    }
    
    /** Select a single file to open, rejects if nothing selected */
    static async selectSingleFile(startIn?: Uri | string): Promise<Uri> {
        const selection = await window.showOpenDialog({
            canSelectMany: false,
            canSelectFiles: true,
            canSelectFolders: false, // .app counts as file
            defaultUri: this.isString(startIn) ? Uri.file(startIn) : startIn,
        });
        
        let path = await this.valueOrReject(selection, true);
        // Try again if a .app folder was selected to allow selecting inside app
        if (path.fsPath.endsWith('.app')) {
            return this.selectSingleFile(path);
        }
        
        return path;
    }
    
    /**
     * Returns the folder path for the given setting or rejects and prompts
     * the user to populate the setting with an info message. If the user presses
     * the button, the open dialog will allow them to select a folder.
     */
    static async getOrPromptForPathSetting(setting: string, prompt: string, action: string): Promise<string> {
        // Workspace API breaks the preference key into two parts, see below
        const components = setting.split('.');
        const key = components.pop();
        setting = components.join('.');
        
        let value: string = workspace.getConfiguration(setting).get(key);
        if (value && value != '') {
            return value;
        }
        
        const choice = await window.showWarningMessage(prompt, action);
        if (choice) {
            value = (await this.selectSingleFolder()).fsPath;
            workspace.getConfiguration(setting).update(key, value);
            return value;
        }
        
        return Promise.reject();
    }
}
