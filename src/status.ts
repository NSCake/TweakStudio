//
//  status.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-07-03
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { LazyGetter } from "lazy-get-decorator";
import { ExtensionContext, StatusBarAlignment, StatusBarItem, window } from "vscode";

export enum Status {
    init_ida = "Waiting for IDA to finish processing",
    init_hopper = "Waiting for Hopper to open",
    
    saving = "Saving Document(s)",
    closing = "Closing Document(s)",
    
    xrefs = "Fetching Xrefs",
    selrefs = "Fetching Selrefs",
    decompile = "Fetching Pseudocode",
    
    loadingProcs = "Procedures",
    loadingSelectorss = "Selectors",
    loadingStrings = "Strings",
    loadingHooks = "%hooks",
}

export class Statusbar {
    /** I actually use this as a queue I guess, but whatever */
    private static stack: { [key: string]: number; } = {};
    
    @LazyGetter()
    private static get status(): StatusBarItem {
        return window.createStatusBarItem(StatusBarAlignment.Left, 0);
    }
    
    /** Build a status string by concatenating all current operations */
    private static get statusString(): string {
        const strings = Object.keys(this.stack)
            .filter(k => this.stack[k] > 0);
        strings.sort();
        return strings.join(', ');
    }
    
    /** Update the status bar to reflect the current status, hiding or showing it as needed */
    private static updateStatus() {
        const string = this.statusString;
        if (string.length) {
            this.status.text = `$(sync~spin) ${string}`;
            this.status.show();
        } else {
            this.status.text = "IDLE";
            this.status.hide();
        }
    }
    
    public static init(context: ExtensionContext) {
        context.subscriptions.push(this.status);
    }
    
    /** Add a new task instance to the status queue */
    public static push(key: string) {
        if (this.stack[key]) {
            this.stack[key]++;
        } else {
            this.stack[key] = 1;
        }
        
        this.updateStatus();
    }
    
    /** Remove an instance of a task from the status queue */
    public static pop(key: string) {
        this.stack[key]--;
        this.updateStatus();
    }
    
    /** Useful when you need to invoke .pop() after a promise with .finally */
    public static popper(key: string): () => void {
        return () => Statusbar.pop(key);
    }
}
