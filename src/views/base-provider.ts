//
//  base-provider.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-04-01
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import { Event, EventEmitter, ProviderResult, TreeDataProvider, TreeItem } from "vscode";
import APIClient from "../api/client";
import { Statusbar } from "../status";

type EventType<E> = E | undefined | null | void;

export default abstract class BaseProvider<T> implements TreeDataProvider<T> {
    private _client?: APIClient;
    /** A string to use for status messages */
    protected abstract statusMessage: string;
    
    private _onDidChangeTreeData: EventEmitter<EventType<T>> = new EventEmitter<EventType<T>>();
    readonly onDidChangeTreeData: Event<EventType<T>> = this._onDidChangeTreeData.event;
    
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }
    
    get client(): APIClient | undefined {
        return this._client;
    }
    
    set client(value: APIClient | undefined) {
        this._client = value;
        this.refresh();
    }
    
    protected abstract reloadData: () => T[] | Promise<T[]>;
    
    protected showStatus = () => {
        Statusbar.push(this.statusMessage);
    }
    
    /**
     * If multiple instances of the same operation are ongoing, this
     * will not actually "clear" the status, but that should be rare.
     */
    protected clearStatus = () => {
        Statusbar.pop(this.statusMessage);
    }
    
    getTreeItem(element: T): TreeItem | Thenable<TreeItem> {
        return element;
    }
    
    getChildren(element?: T): ProviderResult<T[]> {
        if (element || !this.client) return [];
        
        let resultsOrPromise = this.reloadData();
        
        // Only show status if reloadData gave us a promise
        if (!Array.isArray(resultsOrPromise)) {
            this.showStatus();
            resultsOrPromise = resultsOrPromise.finally(this.clearStatus);
        }
        
        return resultsOrPromise;
    }
}
