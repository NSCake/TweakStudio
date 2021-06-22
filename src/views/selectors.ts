//
//  selectors.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { TreeItem, ProviderResult } from 'vscode';
import { Selector } from '../api/model';
import BaseProvider from './base-provider';

export class SelectorsProvider extends BaseProvider<Selector> {
    getTreeItem(element: Selector): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: Selector): ProviderResult<Selector[]> {
        if (element) return [];
        
        return this.client?.listSelectors() || [];
    }
}
