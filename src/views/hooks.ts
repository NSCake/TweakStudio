//
//  hooks.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { Procedure } from '../api/model';
import { Status } from '../status';
import BaseProvider from './base-provider';

export class HooksProvider extends BaseProvider<Procedure> {
    protected statusMessage = Status.loadingHooks;
    protected reloadData = () => this.client?.listProcedures();
}
