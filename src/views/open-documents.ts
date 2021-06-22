//
//  open-documents.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-21
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { TreeItem, ProviderResult } from 'vscode';
import { REDocument } from '../api/model';
import DocumentManager from '../document-manager';
import BaseProvider from './base-provider';

export class OpenDocumentsProvider extends BaseProvider<REDocument> {    
    getTreeItem(element: REDocument): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: REDocument): ProviderResult<REDocument[]> {
        if (element) return [];
        
        return DocumentManager.shared.allDocuments;
    }
}
