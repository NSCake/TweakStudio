//
//  selectors.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-06
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { Selector } from '../api/model';
import { Status } from '../status';
import BaseProvider from './base-provider';

export class SelectorsProvider extends BaseProvider<Selector> {
    protected statusMessage = Status.loadingSelectorss;
    protected reloadData = () => this.client?.listSelectors();
}
