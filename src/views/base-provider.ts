//
//  base-provider.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { Event, EventEmitter, ProviderResult, TreeDataProvider, TreeItem } from "vscode";
import APIClient from "../api/client";

type EventType<E> = E | undefined | null | void;

export default abstract class BaseProvider<T> implements TreeDataProvider<T> {
    private _client?: APIClient;
    
    get client(): APIClient | undefined {
        return this._client;
    }
    
    set client(value: APIClient | undefined) {
        this._client = value;
        this.refresh();
    }
    
    abstract getTreeItem(element: T): TreeItem | Thenable<TreeItem>;
    abstract getChildren(element?: T): ProviderResult<T[]>;
    
    private _onDidChangeTreeData: EventEmitter<EventType<T>> = new EventEmitter<EventType<T>>();
    readonly onDidChangeTreeData: Event<EventType<T>> = this._onDidChangeTreeData.event;
  
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }
}
