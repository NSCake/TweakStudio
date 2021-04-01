//
//  procs.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as vscode from 'vscode';
import { TreeItem, TreeDataProvider, ProviderResult, Event, EventEmitter } from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { String } from '../api/model';
import HopperClient from '../api/hopper';

export class StringsProvider implements TreeDataProvider<String> {
    // private _onDidChangeTreeData: EventEmitter<Symbol | undefined | null | void> = new EventEmitter<Symbol | undefined | null | void>();
    // readonly onDidChangeTreeData: Event<Symbol | undefined | null | void> = this._onDidChangeTreeData.event;

    // refresh(): void {
    //     this._onDidChangeTreeData.fire();
    // }
    
    getTreeItem(element: String): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: String): ProviderResult<String[]> {
        if (element) return [];
        
        return HopperClient.shared.listStrings();
    }
}
