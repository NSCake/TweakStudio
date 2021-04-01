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

type SymbolData = { label: string, address: number, segment: string };
type ProxyResponse<T> = {
    data: T,
    error: string,
}

function isError(obj: any): obj is Error {
    return false;
}

class APIClient {
    protected baseURL: string

    constructor(port: number) {
        this.baseURL = `http://localhost:${port}`;
    }

    // Private //
    
    protected decode<T>(type: new (...args: any[]) => T, args): T {
        return new type(...args);
    }
    
    // decodeList<T>(type: new (...args: any[]) => T, items: any[], args): T[] {
    //     return items.map(s => this.decode(type, args));
    // }
    
    protected decodeProcedures: (symbols: SymbolData[]) => Procedure[] = (items) => {
        return items.map(s => this.decode(Procedure, [s.label, s.address, s.segment]));
    }
    
    protected decodeSymbols: (symbols: SymbolData[]) => Symbol[] = (items) => {
        return items.map(s => this.decode(Symbol, [s.label, s.address, s.segment]));
    }
    
    protected decodeSegments: (names: string[]) => Segment[] = (items) => {
        return items.map(s => this.decode(Segment, [s]));
    }

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
                throw json;
            } else {
                return json;
            }
        });
    }

    protected get<T>(endpoint: string, bodyParams: object = {}): Promise<T> {
        return this.sendRequest('GET', endpoint, bodyParams);
    }

    protected post<T>(endpoint: string, bodyParams: object = {}): Promise<T> {
        return this.sendRequest('POST', endpoint, bodyParams).then((response: ProxyResponse<T>) => {
            if (response.error) {
                throw response.error;
            }
            
            return response.data;
        });
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
    
    listStrings(segment: string = ""): Promise<String[]> {
        return this.post(Endpoint.listStrings, { segment_name: segment }).then(this.decodeSymbols);
    }
    
    // Decompile //
    
    decompileProcedure(segment: string, address: number): Promise<string> {
        return this.post(Endpoint.decompile, { segment_name: segment, procedure_address: address });
    }

    // Search //

    // search(type: SearchType, query: string): Promise<SearchResults> {
    //     return this.l3Post(Endpoint.search, {
    //         mode: "display", type: type, query: query
    //     });
    // }
    
    
}

export default APIClient;
