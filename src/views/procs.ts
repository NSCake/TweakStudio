//
//  procs.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { TreeItem, TreeDataProvider, ProviderResult } from 'vscode';
import { Procedure } from '../api/model';
import HopperClient from '../api/hopper';

export class ProceduresProvider implements TreeDataProvider<Procedure> {
    // private _onDidChangeTreeData: EventEmitter<Symbol | undefined | null | void> = new EventEmitter<Symbol | undefined | null | void>();
    // readonly onDidChangeTreeData: Event<Symbol | undefined | null | void> = this._onDidChangeTreeData.event;

    // refresh(): void {
    //     this._onDidChangeTreeData.fire();
    // }
    
    getTreeItem(element: Procedure): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: Procedure): ProviderResult<Procedure[]> {
        if (element) return [];
        
        return HopperClient.shared.listProcedures();
    }
}
