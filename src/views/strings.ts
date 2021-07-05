//
//  strings.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { String } from '../api/model';
import { Status } from '../status';
import BaseProvider from './base-provider';

export class StringsProvider extends BaseProvider<String> {
    protected statusMessage = Status.loadingStrings;
    protected reloadData = () => this.client?.listStrings();
}
