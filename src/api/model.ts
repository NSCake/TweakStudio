//
//  model.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as vscode from 'vscode';

export class Segment extends vscode.TreeItem {
    constructor(readonly name: string) {
        super(name);
    }
}

export class Symbol extends vscode.TreeItem {
    constructor(
        readonly label: string,
        readonly address: number,
        readonly segment: string,
    ) {
        super(label);
    }
}

export class Xref extends vscode.TreeItem {
    constructor(
        readonly label: string,
        readonly address: number,
    ) {
        super(label);
    }
}

export type String = Symbol;

export class Selector extends Symbol {
    constructor(scheme: string, label: string, address: number, segment: string) {
        super(label, address, segment);
        this.command = {
            command: `${scheme}.show-selrefs`,
            title: 'Show selector refs',
            arguments: [this.address]
        }
    }
}

export class Procedure extends Symbol {
    constructor(scheme: string, label: string, address: number, segment: string) {
        super(label, address, segment);
        this.command = {
            command: `${scheme}.view-pseudocode`,
            title: 'View pseudocode',
            arguments: [this.path]
        }
    }
    
    get path(): string {
        return [this.segment, this.address, this.label].join('/') + '.m';
    }
}
