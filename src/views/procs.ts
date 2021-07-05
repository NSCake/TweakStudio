//
//  procs.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { Procedure } from '../api/model';
import { Status } from '../status';
import BaseProvider from './base-provider';

export class ProceduresProvider extends BaseProvider<Procedure> {
    protected statusMessage = Status.loadingProcs;
    protected reloadData = () => this.client?.listProcedures();
}
