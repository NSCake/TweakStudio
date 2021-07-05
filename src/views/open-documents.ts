//
//  open-documents.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-21
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { REDocument } from '../api/model';
import DocumentManager from '../document-manager';
import BaseProvider from './base-provider';

export class OpenDocumentsProvider extends BaseProvider<REDocument> {
    protected statusMessage: string;
    protected reloadData = () => DocumentManager.shared.allDocuments;
}
