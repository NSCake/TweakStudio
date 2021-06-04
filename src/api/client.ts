//
//  client.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-04
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

import * as fetch from "node-fetch";
import Endpoint from "./endpoints";
import { hostname } from "os";
import { Symbol, Segment, Procedure, String } from "./model";
import { window } from "vscode";

type SymbolData = { label: string, address: number, segment: string };
type ProxyResponse<T> = { data: T }
type ProxyErrorResponse = { data: null, error: string };

function isError(obj: any): obj is Error {
    return false;
}

function isErrorResponse(obj: any): obj is ProxyErrorResponse {
    return obj.error !== undefined && obj.data === null;
}

class APIClient {
    protected port: number;
    protected baseURL: string;
    /** `ida` or `hopper` */
    protected scheme: string;

    constructor(scheme: string, port: number) {
        this.port = port;
        this.scheme = scheme;
        // this.baseURL = `http://localhost:${port}`;
        this.baseURL = `http://localhost.charlesproxy.com:${port}`;
    }

    get id(): string {
        return this.port.toString();
    }

    // Private //
    
    protected decode<T>(type: new (...args: any[]) => T, args): T {
        return new type(...args);
    }
    
    // decodeList<T>(type: new (...args: any[]) => T, items: any[], args): T[] {
    //     return items.map(s => this.decode(type, args));
    // }
    
    protected decodeProcedures: (symbols: SymbolData[]) => Procedure[] = (items) => {
        return items.map(s => this.decode(Procedure, [this.scheme, s.label, s.address, s.segment]));
    }
    
    protected decodeSymbols: (symbols: SymbolData[]) => Symbol[] = (items) => {
        return items.map(s => this.decode(Symbol, [s.label, s.address, s.segment]));
    }
    
    protected decodeSegments: (names: string[]) => Segment[] = (items) => {
        return items.map(s => this.decode(Segment, [s]));
    }

    /** Sends a request with appropriate headers, JSON body, and handles all errors, even in the response. */
    protected sendRequest<T>(method: string, endpoint: string, params: object): Promise<T> {        
        return fetch(this.baseURL + endpoint, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Origin': hostname(),
            },
            body: JSON.stringify(params)
        }) 
        .then(response => {
            return response.json();
        })
        .then(json => {
            if (isError(json)) {
                window.showErrorMessage(json.message);
                throw json;
            } else if (isErrorResponse(json)) {
                window.showErrorMessage(json.error);
                throw json.error;
            } else {
                return json;
            }
        });
    }

    protected get<T>(endpoint: string, bodyParams: object = {}): Promise<T> {
        return this.sendRequest('GET', endpoint, bodyParams);
    }

    protected post<T>(endpoint: string, bodyParams: object = {}): Promise<T> {
        return this.sendRequest('POST', endpoint, bodyParams).then((r: ProxyResponse<T>) => r.data);
    }

    protected parseIntsToStrings<T>(obj: any): T {
        for (let key in obj) {
            if (!isNaN(obj[key]) && obj[key] !== null) {
                obj[key] = parseInt(obj[key]);
            }
        }

        return obj;
    }
    
    // Misc //
    
    executeRawCommand(cmd: string): Promise<string> {
        return this.post(Endpoint.rawCommand, { cmd: cmd })
    }
    
    // List //
    
    listSegments(): Promise<Segment[]> {
        return this.post(Endpoint.listSegments).then(this.decodeSegments);
    }
    
    listProcedures(segment: string = ""): Promise<Procedure[]> {
        return this.post(Endpoint.listProcedures, { segment_name: segment }).then(this.decodeProcedures);
    }
    
    listStrings(): Promise<String[]> {
        return this.post(Endpoint.listStrings).then(this.decodeSymbols);
    }
    
    // Decompile //
    
    decompileProcedure(address: number): Promise<string> {
        return this.post(Endpoint.decompile, { procedure_address: address });
    }

    // Search //

    // search(type: SearchType, query: string): Promise<SearchResults> {
    //     return this.l3Post(Endpoint.search, {
    //         mode: "display", type: type, query: query
    //     });
    // }
    
    // Shutdown //
    
    shutdown(saveOrNot: boolean = false): Promise<void> {
        return this.post(Endpoint.shutdown, { save: saveOrNot });
    }
}

export default APIClient;
