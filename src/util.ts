//
//  util.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-27
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { exec } from "child_process";
import { QuickPickItem, window } from "vscode";

export class Util {
    
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
            exec(`otool -l '${path}' | grep cryptid`, (error, stdout, stderr) => {
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
        return new Promise(async (resolve, reject) => {
            const choice = await window.showQuickPick(choices, { canPickMany: false });
            if (choice) {
                resolve(choice);
            } else {
                reject();
            }
        });
    }
}
