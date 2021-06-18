//
//  ida.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-03-04
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

interface IDATokenInfoData {
    obj_ea: number,
    lvar: number,
    name: string | null,
}

export class IDATokenInfo {
    typename: string
    constructor(
        readonly data: IDATokenInfoData,
        readonly type: IDATokenType,
        readonly idx: number,
    ) {
        this.typename = IDATokenType[this.type];
    }
}

enum IDATokenType {
    empty = 0,
    comma = 1,
                
    asg = 2,      //  = 
    asgbor = 3,   // |=
    asgxor = 4,   // ^=
    asgband = 5,  // &=
    asgadd = 6,   // +=
    asgsub = 7,   // -=
    asgmul = 8,   // *=
    asgsshr = 9,  // >>= signed
    asgushr = 10, // >>= unsigned
    asgshl = 11,  // <<=
    asgsdiv = 12, // /= signed
    asgudiv = 13, // /= unsigned
    asgsmod = 14, // %= signed
    asgumod = 15, // %= unsigned
    
    tern = 16,    // ?:
    lor = 17,     // ||
    land = 18,    // &&
    bor = 19,     // |
    xor = 20,     // ^
    band = 21,    // &
    eq = 22,      // ==
    ne = 23,      // !=
    sge = 24,     // >= signed
    uge = 25,     // >= unsigned
    sle = 26,     // <= signed
    ule = 27,     // <= unsigned
    sgt = 28,     // > signed
    ugt = 29,     // > unsigned
    slt = 30,     // < signed
    ult = 31,     // < unsigned
    sshr = 32,    // >> signed
    ushr = 33,    // >> unsigned
    shl = 34,     // <<
    add = 35,     // +
    sub = 36,     // -
    mul = 37,     // *
    sdiv = 38,    // / signed
    udiv = 39,    // / unsigned
    smod = 40,    // % signed
    umod = 41,    // % unsigned
    fadd = 42,    // + fp
    fsub = 43,    // - fp
    fmul = 44,    // * fp
    fdiv = 45,    // / fp
    fneg = 46,    // -x fp
    neg = 47,     // -x
    cast = 48,    // (T)x
    lnot = 49,    // !
    bnot = 50,    // ~
    deref = 51,   // * dereference
    
    ref = 52,     // &x
    postinc = 53, // X++
    postdec = 54, // X--
    preinc = 55,  // ++X
    predec = 56,  // --X
    call = 57,    // f()
    idx = 58,     // x[y]
    memref = 59,  // x.y
    memptr = 60,  // x->y
    num = 61,     // 5
    fnum = 62,    // 3.15
    str = 63,     // "hi"
    symbol = 64,  // address
    variable = 65,// variable
    insn = 66,    // instruction
    sizeof = 67,  // sizeof(x)
    helper = 68,  // arbitrary name
    type = 69,    // arbitrary type
    last = type,  // ?
    
    emptyStmt = 70,
    block = 71,
    expr = 72,
    if = 73,
    for = 74,
    while = 75,
    do = 76,
    switch = 77,
    break = 78,
    continue = 79,
    return = 80,
    goto = 81,
    asm = 82,
    end = 83
}

export default IDATokenType;
