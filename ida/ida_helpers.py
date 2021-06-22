#
#  ida_helpers.py
#  Tweak Studio
#  
#  Created by Tanner Bennett on 2021-06-22
#  Copyright (c) 2021 Tanner Bennett. All rights reserved.
#

import itertools
import types

import FIDL.decompiler_utils as du
from ida_hexrays import *
from idautils import *
from idaapi import *
from idc import *
import sark

jsonTypes = [str, int, float, bool, long]
collections = [dict, list, itertools.imap, types.GeneratorType]
nonListLists = [itertools.imap, types.GeneratorType]
excluded = [ida_funcs.func_t]

def decomp(addr):
    # Decompile this function
    cfunc = decompile(addr) # type: cfuncptr_t
    psc = cfunc.pseudocode # type: strvec_t
    return (cfunc, psc)

def safe_getattr(obj, key):
    try:
        return getattr(obj, key)
    except:
        return None

def reflect(obj):
    if obj is None:
        return None
    
    # if isinstance(obj, Generator)
        
    cls = type(obj)
    
    if cls in jsonTypes:
        return obj
    
    if cls in collections:
        if isinstance(obj, list):
            return [reflect(e) for e in obj]
        # elif cls in nonListLists:
        #     return [reflect(e) for e in list(obj)]
        elif isinstance(obj, dict):
            return { k: reflect(v) for k, v in obj.items() }
        else:
            return 'collection?'
        
    keys = [p for p in dir(cls) if isinstance(getattr(cls,p), property)]
    values = [reflect(safe_getattr(obj, key)) for key in keys]
    props = {}
    for pair in zip(keys, values):
        props[pair[0]] = pair[1]
    
    return props if props != {} else str(cls)

def segment_containsLine(self, line):
    return (line.startEA >= self.startEA) and (line.startEA < self.endEA)

def function_containsAddress(self, addr):
    return (addr >= self.startEA) and (addr < self.endEA)
    
def citem_by_pos(psc, lineno, col):
    """
    Return the ctree item index corresponding to a zero-based (line, column) position.
    """
    
    if lineno >= psc.size():
        raise Exception("Line index out of bounds for function")
    
    line = psc[lineno].line

    # Position in the actual string, including color codes
    i = 0
    # Position in the displayed string, no color codes
    c = 0
    last_idx = None
    line_length = len(line)
    
    if col >= line_length:
        raise Exception("Column index out of bounds for line")

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:
        
        # Did we finally reach the given column?
        if c >= col:
            return last_idx

        # does this character mark the start of a new COLOR_* token?
        if line[i] == COLOR_ON:
            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == COLOR_ADDR:
                # yes, so move past the COLOR_ADDR byte
                i += 1

                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                citem_index = int(line[i:i + COLOR_ADDR_SIZE], 16)
                i += COLOR_ADDR_SIZE

                # SANITY CHECK
                # NOTE: this value is arbitrary (although reasonable)
                # FIX: get this from cfunc.treeitems.size()
                if citem_index < 0x1000:
                    # save the extracted citem index
                    last_idx = citem_index
            
            # skip past the color code
            else:
                i += 1
        # does this character mark the end of a color code tag?
        elif line[i] == COLOR_OFF:
            # skip past COLOR_OFF as well as the color code
            i += 2
        
        # nothing we care about happened, keep lexing forward
        else:
            i += 1
            c += 1

    # Impossible!
    raise Exception("Fatal error in citem_by_pos(): (c: " + str(c) + ", col: " + str(col) + ")")

def pscDataForAddress(addr):
    # Iterate over all functions until we find the one containing this address
    allfuncs = sark.Segment(name='__text').functions
    for func in allfuncs:
        if func.containsAddress(addr):
            # Decompile this function
            cfunc = decompile(func.startEA) # type: cfuncptr_t
            psc = cfunc.pseudocode # type: strvec_t
            
            # Map...
            
            # Line numbers to groups of citems per line
            linesToCItems = {}
            for lineNumber in range(psc.size()):
                lineText = psc[lineNumber].line
                # Parse out citem indexes from the line's tags
                linesToCItems[lineNumber] = du.lex_citem_indexes(lineText)
            
            # Citem indexes to line numbers
            citemsToLines = {}
            for lineno, citems in linesToCItems.items():
                for citemIdx in citems:
                    citemsToLines[citemIdx] = lineno
            
            # Line numbers (1-indexed) to line content
            codeLines = {}
            for idx, sline in enumerate(psc):
                # tag_remove removes the color codes
                codeLines[idx + 1] = tag_remove(sline.line)

            # Now, find the nearest line to our address
            for item in cfunc.treeitems:
                # Citem addresses may be off by as much as 4
                if abs(item.ea - addr) <= 4:
                    # Get the line number and return the data
                    lineno = citemsToLines[item.index] + 1
                    return (lineno, {
                        "address": addr,
                        "functionName": sark.demangle(func.name, 8),
                        "functionDecl": func.demangled,
                        "functionAddress": func.startEA,
                        "lineNumber": lineno,
                        "lineContent": codeLines[lineno],
                    })
    
    return (-1, None)

sark.Segment.containsLine = segment_containsLine
sark.Function.containsAddress = function_containsAddress    
