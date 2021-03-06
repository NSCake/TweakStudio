//
//  model.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as vscode from 'vscode';
import { Util } from '../util';
import { Disassembler } from './client';

export class REDocument extends vscode.TreeItem {
    /** The name of the file, such as glibc.dylib or Uber.idb */
    readonly filename: string;
    /** The directory the file is open in */
    readonly directory: string;
    /** Whether the open file has yet been saved as/is a project */
    readonly isProject: boolean;
    
    /** Make this docuemnt indicate whether it is active or not */
    set active(active: boolean) {
        if (active) {
            this.label = `⭑ ${this.filename} (${this.directory})`;
        } else {
            this.label = `${this.filename} (${this.directory})`
        }
    }
    
    /** The database file extension to use for this document */
    private get saveExtension(): 'i64' | 'hop' {
        if (this.family == 'ida') {
            return 'i64';
        }
        
        return 'hop';
    }
    
    /** Where to save this file by default depending on whether it is a project or not */
    get defaultSaveAs(): string {
        if (this.isProject) {
            return this.path;
        }
        
        return `${this.path}.${this.saveExtension}`;
    }
    
    /** Files to be deleted when the project is closed or deleted */
    get cleanupFiles(): string[] {
        if (this.family == 'ida') {
            return [Util.popLast(this.filename, '.') + '.til']
                .map(name => `${this.directory}/${name}`);
        }

        return [];
    }
    
    constructor(readonly path: string, readonly family: Disassembler) {
        super('');
        this.isProject = path.match(/\.(idb|i64|hop)/) != null;
        
        let folder = path.split('/'); ;
        this.filename = folder.pop();
        this.directory = folder.join('/');
        
        this.active = false;
        
        this.command = {
            command: 'tweakstudio.activate-document',
            title: 'Switch to this document',
            arguments: [this]
        }
    }
}

export class Segment extends vscode.TreeItem {
    constructor(readonly name: string) {
        super(name);
    }
}

export class Symbol extends vscode.TreeItem {
    constructor(
        readonly scheme: string,
        readonly label: string,
        readonly address: number,
        readonly segment: string,
    ) {
        super(label);
        this.command = {
            command: `${scheme}.show-xrefs`,
            title: 'Show xrefs',
            arguments: [this.address]
        }
    }
}

export class Xref implements vscode.QuickPickItem {
    constructor(
        readonly address: number,
        readonly functionName: string,
        readonly functionDecl: string,
        readonly functionAddress: number,
        readonly lineNumber: number,
        readonly lineContent: string,
    ) { }
    
    get label(): string {
        return `${this.functionName}:${this.lineNumber}`
    }
    
    get detail(): string {
        return this.lineContent;
    }
    
    get path(): string {
        return ['__text', this.functionAddress, this.functionName].join('/') + '.m';
    }
    
    get action(): vscode.Command {
        const scheme = 'ida'; // For now, only IDA supports this
        return {
            command: `${scheme}.view-pseudocode`,
            title: 'Show reference in pseudocode',
            arguments: [this.path, this.lineNumber]
        }
    }
}

export type String = Symbol;

export class Selector extends Symbol {
    constructor(scheme: string, label: string, address: number, segment: string) {
        super(scheme, label, address, segment);
        this.command = {
            command: `${scheme}.show-selrefs`,
            title: 'Show selector refs',
            arguments: [this.address]
        }
    }
}

export class Procedure extends Symbol {
    constructor(
        scheme: string,
        readonly name: string,
        readonly decl: string,
        readonly address: number,
        readonly segment: string
    ) {
        // We want the declaration displayed instead of the name
        super(scheme, decl, address, segment);
        this.command = {
            command: `${scheme}.view-pseudocode`,
            title: 'View pseudocode',
            arguments: [this.path]
        }
    }
    
    get path(): string {
        return [this.segment, this.address, this.name].join('/') + '.m';
    }
    
    static parseURI(uri: vscode.Uri): { segment: string, addr: number, name: string } | undefined {
        const components = uri.path.split('/');
        if (components.length != 4) {
            return undefined;
        }
        
        return { segment: components[1], addr: parseInt(components[2]), name: components[3] };
    }
}
