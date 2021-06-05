//
//  selectors.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as vscode from 'vscode';
import { TreeItem, ProviderResult } from 'vscode';
import { Selector } from '../api/model';
import BaseProvider from './base-provider';

export class SelectorsProvider extends BaseProvider<Selector> {
    // private _onDidChangeTreeData: EventEmitter<Symbol | undefined | null | void> = new EventEmitter<Symbol | undefined | null | void>();
    // readonly onDidChangeTreeData: Event<Symbol | undefined | null | void> = this._onDidChangeTreeData.event;

    // refresh(): void {
    //     this._onDidChangeTreeData.fire();
    // }
    
    getTreeItem(element: Selector): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: Selector): ProviderResult<Selector[]> {
        if (element) return [];
        
        return this.client?.listSelectors() || [];
    }
}
