//
//  endpoints.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-04
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

enum Endpoint {
    rawCommand = "/cmd",
    
    listSegments = "/segments",
    listProcedures = "/procedures",
    listStrings = "/strings",
    listSelrefs = "/sel_xrefs",
    listXrefs = "/xrefs",
    symbolForAddress = "/symbolicate",
    
    decompile = "/decompile",
    disassemble = "/disassemble",
    cursorExprInfo = "/expr_at_pos",
    editorAction = "/editor_action",
    
    save = "/save",
    shutdown = "/shutdown",
}

export default Endpoint;
