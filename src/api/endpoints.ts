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
    
    decompile = "/decompile",
    
    shutdown = "/shutdown",
}

export default Endpoint;
