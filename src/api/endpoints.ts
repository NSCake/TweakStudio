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
    
    addComment = "/add_comment",
    
    decompile = "/decompile",
    
    shutdown = "/shutdown",
}

export default Endpoint;
