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

collections = [dict, list, itertools.imap, types.GeneratorType]
nonListLists = [itertools.imap, types.GeneratorType]
excluded = [ida_funcs.func_t]


def safe_getattr(obj, key):
    """`getattr()` without crashing."""
    try:
        return getattr(obj, key)
    except:
        return None

def reflect(obj):
    """For debugging only. Reflect an object into a dictionary."""
    if obj is None:
        return None
        
    cls = type(obj)
    
    if cls in [str, int, float, bool, long]:
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


def decomp(addr):
    """Return the `cfunc_t` and its pseudocode as a tuple for a given address"""
    # Decompile this function
    cfunc = decompile(addr) # type: cfuncptr_t
    psc = cfunc.pseudocode # type: strvec_t
    return (cfunc, psc)

def citem_by_pos(psc, lineno, col):
    """
    Return the `citem_t` index corresponding to a zero-based (line, column) position.
    This number is an index into `cfuncptr_t.treeitems`
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

def citemData(funcAddr):
    """
    Return various information about the citems in a given function.
    This includes:
    - the `cfuncptr_t` itself
    - a map of line numbers to `citem_t`'s for that line
    - a map of `citem_t` indexes (in `cfuncptr_t.treeitems`) to line numbers
    - a list of pseudocode lines with color tags removed
    
    `cfunc, linesToCItems, citemsToLines, codeLines = ...`
    """
    # Decompile this function
    cfunc = decompile(funcAddr) # type: cfuncptr_t
    psc = cfunc.pseudocode # type: strvec_t
    
    # Map...
    
    # Line numbers to groups of citems per line
    linesToCItems = {} # type: dict[int, list[citem_t]]
    for lineNumber in range(psc.size()):
        lineText = psc[lineNumber].line
        # Parse out citem indexes from the line's tags
        linesToCItems[lineNumber] = du.lex_citem_indexes(lineText)
    
    # Citem indexes to line numbers
    citemsToLines = {} # type: dict[int, int]
    for lineno, citems in linesToCItems.items():
        for citemIdx in citems:
            citemsToLines[citemIdx] = lineno
    
    # Line numbers (1-indexed) to line content
    codeLines = {} # type: dict[int, str]
    for idx, sline in enumerate(psc):
        # tag_remove removes the color codes
        codeLines[idx + 1] = tag_remove(sline.line)
    
    return (cfunc, linesToCItems, citemsToLines, codeLines)

def pscDataForAddress(addr):
    """Return snippet-like pseudocode data for a given address."""
    # Iterate over all functions until we find the one containing this address
    allfuncs = sark.Segment(name='__text').functions
    for func in allfuncs:
        if func.containsAddress(addr):
            cfunc, _, citemsToLines, codeLines = citemData(func.startEA)

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

# Sark extensions #

def create_comment(cfunc, addr, comment):
    # type:(cfuncptr_t, int, str) -> bool
    """
    Displays a comment at the line corresponding to the given address.
    
    Cannot use the function from FIDL because the version we use only
    uses `ITP_SEMI` which will not always work for any line.
    """

    tl = treeloc_t()
    tl.ea = addr
    
    # Iterate over every ITP type and try to set a comment for this line. Shiiiiii
    itps = [ITP_SEMI, ITP_CURLY1, ITP_CURLY2, ITP_COLON, ITP_BRACE1, ITP_BRACE2, ITP_ASM, ITP_ELSE, ITP_DO, ITP_CASE]
    for itp in itps + list(range(65)): # Range covers ITP_ARG1 to ITP_ARG64 and ITP_EMPTY(0)
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        # Trigger string representation, else orphan comments aren't detected
        cfunc.__str__()
        
        # Did it work? Stop if it worked
        if not cfunc.has_orphan_cmts():
            return True
        
        # Otherwise, remove that orphan comment and try the next one
        cfunc.del_orphan_cmts()
    
    return False

def segment_containsLine(self, line):
    # type:(sark.Segment, sark.Line) -> bool
    return (line.startEA >= self.startEA) and (line.startEA < self.endEA)

def function_containsAddress(self, addr):
    # type:(sark.Function, int) -> bool
    return (addr >= self.startEA) and (addr < self.endEA)

sark.Segment.containsLine = segment_containsLine
sark.Function.containsAddress = function_containsAddress    
