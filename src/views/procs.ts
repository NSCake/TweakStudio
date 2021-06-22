//
//  procs.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { TreeItem, ProviderResult } from 'vscode';
import { Procedure } from '../api/model';
import BaseProvider from './base-provider';

export class ProceduresProvider extends BaseProvider<Procedure> {    
    getTreeItem(element: Procedure): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: Procedure): ProviderResult<Procedure[]> {
        if (element) return [];
        
        return this.client?.listProcedures() || [];
    }
}
