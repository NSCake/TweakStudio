//
//  util.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-27
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { exec } from "child_process";
import { resolve } from "node:path";
import { QuickPickItem, window } from "vscode";

export class Util {
    
    /**
     * Returns a list of architecture strings (in slice order) or rejects if not a Mach-O.
     * One architecture means it is not a FAT binary.
     */
    static archsForFile(path: string): Promise<string[]> {
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
