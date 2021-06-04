//
//  bootstrap.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-02
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

export default interface DisassemblerBootstrap {
    /**
     * Start a new disassembler instance with the given path.
     * @param path A path to existing instance data or an executable file.
     * @return The port associated with the new proxy instance to pull data from.
     */
    openFile(path: string): Promise<number>;
}
