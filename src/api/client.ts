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
import { Symbol, Segment, Procedure, String, Selector, Xref, REDocument } from "./model";
import { window } from "vscode";
import IDATokenType, { IDATokenInfo } from "./ida";
import HopperClient from "./hopper";
import { ChildProcess } from "node:child_process";

type ProxyResponse<T> = { data: T }
type ProxyErrorResponse = { data: null, error: string };
type LabelData = { label: string, address: number, segment: string };
type ProcData = LabelData & { decl: string };

export type Disassembler = 'ida' | 'hopper';

export type CodeLine = {
    funcAddr: number;
    /** Zero-based line number */
    lineno: number;
};
export type CursorPosition = CodeLine & {
    /** Zero-based column index */
    col: number;
};

export enum EditorAction {
    renameVar = 1,
    renameSymbol,
    listXrefs,
    addComment,
    clearComment,
    addVArg,
    removeVArg,
}

/** 
 * We only care about xrefs within functions since we automate
 * the process of finding a selector, finding the matching selref,
 * and then looking at the references in code. Also, we only
 * provide a way to look at references within psc or disasm anyway.
 */
type XrefData = {
    address: number,
    functionName: string,
    functionDecl: string,
    functionAddress: number,
    lineNumber: number,
    lineContent: string,
};

function isError(obj: any): obj is Error {
    return false;
}

function isErrorResponse(obj: any): obj is ProxyErrorResponse {
    return obj.error !== undefined && obj.data === null;
}

export interface IIDAClient {
    getTokenTypeAtPosition(position: CursorPosition): Promise<IDATokenType>;
}

export interface APIClientConfig {
    scheme: Disassembler;
    port: number;
    process: ChildProcess;
    file: string;
}

abstract class APIClient {
    protected port: number;
    protected baseURL: string;
    public scheme: Disassembler;
    public filepath: string;
    public document: REDocument;
    public process: ChildProcess;

    constructor(config: APIClientConfig) {
        this.port = config.port;
        this.scheme = config.scheme;
        this.filepath = config.file;
        this.process = config.process;
        this.baseURL = `http://localhost:${this.port}`;
        // this.baseURL = `http://localhost.charlesproxy.com:${this.port}`;
        
        this.document = new REDocument(config.file, config.scheme);
    }

    get id(): string {
        return this.port.toString();
    }
    
    get ida(): IDAClient | undefined {
        return undefined;
    }
    
    // get hopper(): HopperClient | undefined {        
    //     return undefined;
    // }

    // Private //
    
    protected decode<T>(type: new (...args: any[]) => T, args): T {
        return new type(...args);
    }
    
    // decodeList<T>(type: new (...args: any[]) => T, items: any[], args): T[] {
    //     return items.map(s => this.decode(type, args));
    // }
    
    protected decodeProcedures: (symbols: ProcData[]) => Procedure[] = (items) => {
        return items.map(s => this.decode(Procedure, [this.scheme, s.label, s.decl, s.address, s.segment]));
    }
    
    protected decodeSymbols: (symbols: LabelData[]) => Symbol[] = (items) => {
        return items.map(s => this.decode(Symbol, [this.scheme, s.label, s.address, s.segment]));
    }
    
    protected decodeSelectors: (symbols: LabelData[]) => Symbol[] = (items) => {
        return items.map(s => this.decode(Selector, [this.scheme, s.label, s.address, s.segment]));
    }
    
    protected decodeXrefs: (symbols: XrefData[]) => Xref[] = (items) => {
        return items.map(s => this.decode(Xref, [
            s.address,
            s.functionName,
            s.functionDecl,
            s.functionAddress,
            s.lineNumber,
            s.lineContent.trim()
        ]));
    }
    
    protected decodeSegments: (names: string[]) => Segment[] = (items) => {
        return items.map(s => this.decode(Segment, [s]));
    }
    
    protected decodeToken: (token: any) => IDATokenInfo = (token) => {
        return this.decode(IDATokenInfo, [token.data, token.type, token.idx]);
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
        return this.post(Endpoint.listStrings, {
            segment_names: ['__cstring', '__cfstring']
        }).then(this.decodeSymbols);
    }
    
    listSelectors(): Promise<Selector[]> {
        return this.post(Endpoint.listStrings, {
            segment_names: ['__objc_methname']
        }).then(this.decodeSelectors);
    }
    
    listSelrefs(stringAddress: number): Promise<Xref[]> {
        return this.post(Endpoint.listSelrefs, {
            string_address: stringAddress
        }).then(this.decodeXrefs);
    }
    
    listXrefs(address: number): Promise<Xref[]> {
        return this.post(Endpoint.listXrefs, {
            address: address
        }).then(this.decodeXrefs);
    }
    
    
    // Pseudocode //
    
    decompileProcedure(address: number): Promise<string> {
        return this.post(Endpoint.decompile, { procedure_address: address });
    }
    
    // Editor actions //
    
    canPerformActionOnToken(action: EditorAction, type: IDATokenType): boolean {
        switch (action) {
            case EditorAction.renameVar: return type == IDATokenType.variable;
            case EditorAction.renameSymbol: return type == IDATokenType.symbol;
            case EditorAction.listXrefs: return type == IDATokenType.symbol;
            case EditorAction.addComment: return true;
            case EditorAction.clearComment: return true;
            case EditorAction.addVArg: break;
            case EditorAction.removeVArg: break;
            default: return false;
        }
    }
    
    addComment(pos: CodeLine, comment: string): Promise<boolean> {
        return this.post(Endpoint.editorAction, { action: EditorAction.addComment, args: {
            funcAddr: pos.funcAddr, line: pos.lineno, comment: comment
        }});
    }
    
    // Document management //
    
    async save(as?: string): Promise<void> {
        await this.post(Endpoint.save, { outfile: as });
        
        // Update file paths if we had a raw binary open before
        if (!this.document.isProject) {
            this.document = new REDocument(as ?? this.document.defaultSaveAs, this.scheme);
            this.filepath = this.document.path;
        }
    }
    
    shutdown(saveOrNot: boolean = false): Promise<void> {
        return this.post(Endpoint.shutdown, { save: saveOrNot });
    }
}

export class IDAClient extends APIClient {
    getTokenInfoAtPosition(position: CursorPosition): Promise<IDATokenInfo> {
        return this.post(Endpoint.cursorExprInfo, {
            addr: position.funcAddr, line: position.lineno, col: position.col
        }).then(this.decodeToken);
    }
    
    /**
     * Rename a local variable in the given function with the given citem index.
     * Omit newName to clear the previously saved name.
     */
    renameLvar(funcAddr: number, idx: number, newName?: string): Promise<boolean> {
        return this.post(Endpoint.editorAction, { action: EditorAction.renameVar, args: {
            funcAddr: funcAddr, idx: idx, name: newName, clear: !newName?.length
        }});
    }
    
    get ida(): IDAClient | undefined {
        return this;
    }
}

export default APIClient;
