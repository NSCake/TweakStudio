//
//  strings.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { TreeItem, ProviderResult } from 'vscode';
import { String } from '../api/model';
import BaseProvider from './base-provider';

export class StringsProvider extends BaseProvider<String> {
    getTreeItem(element: String): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: String): ProviderResult<String[]> {
        if (element) return [];
        
        return this.client?.listStrings() || [];
    }
}
