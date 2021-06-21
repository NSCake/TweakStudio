#
#  ida/proxy.py
#  Tweak Studio
#
#  Created by Tanner Bennett on 2021-05-24
#  Originated from file created by Ethan Arbuckle on 2021-03-05
#  Copyright (c) 2021 Ethan Arbuckle and Tanner Bennett. All rights reserved.
#
#  References and libraries used:
#  Demangle inhibitor flags: https://github.com/rcx/ida-scripts/blob/master/cfg/ida.cfg
#  Sark: https://github.com/tmr232/Sark
#  FIDL: https://github.com/fireeye/FIDL
#

import json
import traceback
import http.client
import os
from enum import IntEnum
from http.server import BaseHTTPRequestHandler, HTTPServer
import FIDL.decompiler_utils as du
from ida_hexrays import *
from idautils import *
from idaapi import *
from idc import *
import sark

import itertools
import types

class EditorAction(IntEnum):
    renameVar = 1,
    renameSymbol = 2,
    listXrefs = 3,
    addComment = 4,
    clearComment = 5,
    addVArg = 6,
    removeVArg = 7,

load_plugin('hexx64')
load_plugin('hexarm64')
autoWait()

# Available segment names:
# HEADER
# __text
# __picsymbolstub4
# __stub_helper
# __gcc_except_tab
# __cstring
# __objc_methname
# __nl_symbol_ptr
# __la_symbol_ptr
# __mod_init_func
# __cfstring
# __objc_imageinfo
# __objc_selrefs
# __objc_classrefs
# __data
# __common
# __bss
# UNDEF

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


class dbg_LineData:
    PATH = "/line_data"
    
    @classmethod
    def run(cls, addr, line):
        cfunc, psc = decomp(addr)
        t = psc[line].line
        return {'line': tag_remove(t), 'bytes': bytes(t.encode("utf-8")),
            'tags': {
                'COLOR_ON': str(COLOR_ON),
                'COLOR_OFF': str(COLOR_OFF),
                'COLOR_ADDR': str(COLOR_ADDR),
                'COLOR_ESC': str(COLOR_ESC),
                'COLOR_INV': str(COLOR_INV),
            }
        }


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
    

server = 0
wantsShutdown = False

class Shutdown:
    PATH = "/shutdown"

    @classmethod
    def run(cls, save):
        save_database('', 0 if save else DBFL_KILL | DBFL_TEMP)
        wantsShutdown = True
        return {}


class ListSegments:
    PATH = "/segments"

    @classmethod
    def run(cls):
        return [segment.name for segment in sark.segments()]


class ListProcedures:
    PATH = "/procedures"

    @classmethod
    def run(cls, segment_name):
        if not segment_name:
            allProcs = map(cls.procsForSegment, ListSegments.run())
            return sum(allProcs, [])
        else:
            return cls.procsForSegment(segment_name)

    @classmethod
    def procsForSegment(cls, segment_name):
        if not segment_name:
            raise Exception("did not specify a segment name")

        segment = sark.Segment(name=segment_name)

        named_procedures = []
        for function in segment.functions:
            named_procedures.append(
                {
                    "label": sark.demangle(function.name, 8),
                    "decl": function.demangled,
                    "address": function.startEA,
                    "segment": segment_name,
                    # "obj": reflect(function)
                }
            )

        return named_procedures


class ListStrings:
    PATH = "/strings"

    @classmethod
    def run(cls, segment_names):
        strings = []
        for sname in segment_names:
            seg = sark.Segment(name=str(sname)) # sname is type 'unicode' here???
        
            for line in seg.lines:
                if line.is_string:
                    strings.append(
                        {
                            "label": line.bytes,
                            "address": line.startEA,
                            "segment": sname,
                        }
                    )
                
        return strings


class ListSelectorXRefs:
    PATH = "/sel_xrefs"
    
    @classmethod
    def run(cls, string_address):
        selrefs = sark.Segment(name='__objc_selrefs')
        
        # Get the line for this selector
        line = sark.Line(ea=string_address)
        if not line:
            return []
        
        # Enumerate all references to this selector
        for xr in line.xrefs_to:
            sel = sark.Line(ea=xr.frm)
            # ... until we find the (first) selref pointing to this selector
            if sel and selrefs.containsLine(sel):
                # Then, list all references to that selref
                refs = [ref for ref in sel.drefs_to]
                results = {}
                # Loop over each selref ref and find the pseudocode
                for ref in refs:
                    lineno, data = pscDataForAddress(ref)
                    # Store first ref for each line number
                    if data and not lineno in results:
                        results[lineno] = data
                
                return results.values()
        
        # Probably not a selector, or has no references
        return []
                    

class ListXrefs:
    PATH = "/xrefs"

    @classmethod
    def run(cls, address):
        line = sark.Line(ea=address)
        if not line:
            return []
        
        # Enumerate all references to this address
        results = {}
        for ref in line.drefs_to:
            lineno, data = pscDataForAddress(ref)
            # Store first ref for each line number
            if data and not lineno in results:
                results[lineno] = data
        
        return results.values()


class SymbolForAddress:
    PATH = "/symbolicate"
    
    @classmethod
    def run(cls, addr):
        line = sark.Line(ea=addr)
        if line:
            return line.name
        
        return None


class DecompileProcedure:
    PATH = "/decompile"

    @classmethod
    def run(cls, procedure_address):
        # if not init_hexrays_plugin(PLUGIN_PROC):
        #     raise Exception("Plugin or script not compatible with decompiler")
            
        if not procedure_address:
            raise Exception("did not specify procedure address")

        procedure_candidate = sark.Function(ea=procedure_address)        
        if procedure_candidate:
            cfunc = decompile(procedure_address) # type: cfuncptr_t
            return str(cfunc)

        raise Exception("Failed to find the specified procedure")


class ListProcedureCTreeItems:
    PATH = "/ctree_items"

    @classmethod
    def run(cls, addr):
        
        # Map line numbers to groups of citems per line
        # linesToCItems = {}
        # for lineNumber in range(psc.size()):
        #     lineText = psc[lineNumber].line
        #     # Parse out citem indexes from the line's tags
        #     linesToCItems[lineNumber] = du.lex_citem_indexes(lineText)
        
        return []


class ExprTypeUnderCursor:
    PATH = "/expr_at_pos"
    
    @classmethod
    def run(cls, addr, line, col):
        cfunc, psc = decomp(addr)
        idx = citem_by_pos(psc, line, col)
        if idx:
            expr = cfunc.treeitems[idx].cexpr # type: cexpr_t
            obj_ea = expr.x.obj_ea if expr.op == cot_ref else expr.obj_ea
            var = cfunc.lvars[expr.v.idx].name if expr.op == cot_var else None
            return {
                'type': expr.op,
                'citem': idx,
                'data': {
                    'name': var if var else SymbolForAddress.run(obj_ea),
                    'lvar': expr.v.idx if var else -1,
                    'obj_ea': obj_ea,
                }
            }
        
        # No expr under cursor
        return {'type': -1}


class DisassembleProcedure:
    PATH = "/disassemble"

    @classmethod
    def run(cls, proc_address):
        if not proc_address:
            raise Exception("did not specify procedure address")

        disassembly = ""

        proc_name = idc.get_func_name(proc_address)
        proc = sark.Function(name=proc_name, address=proc_address)
        
        if proc:
            for line in proc.lines:
                disassembly += line.disasm + "\n"
        # Maybe this should return a list of instructions, instead of combining them into 1 string?
        return disassembly


class PerformEditorAction:
    PATH = "/editor_action"
    
    @classmethod
    def run(cls, action, args):
        if not action:
            return None
        
        if action == EditorAction.addComment:
            return False
        elif action == EditorAction.renameVar:
            # lineno = args.line
            # col = args.col
            funcAddr = args['funcAddr']
            itemIdx = args['idx']
            name = args['name']
            clear = args['clear']
            
            window = open_pseudocode(funcAddr, False) # type: vdui_t
            cfunc = decompile(funcAddr) # type: cfuncptr_t
            return window.rename_lvar(cfunc.lvars[itemIdx], name.encode("utf-8"), not clear)
        
        else:
            return False
        



class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        posted_data = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        data_response = None
        error = None

        for handler in [
            Shutdown,
            ListSegments,
            ListProcedures,
            ListStrings,
            ListSelectorXRefs,
            ListXrefs,
            SymbolForAddress,
            DecompileProcedure,
            DisassembleProcedure,
            ExprTypeUnderCursor,
            PerformEditorAction,
            
            dbg_LineData,
        ]:
            if self.path == handler.PATH:
                try:
                    data_response = handler.run(**posted_data)
                    self.respond(200, data_response)
                except TypeError as e:
                    error = str(e) + '\n' + traceback.format_exc()
                    self.respond(500, None, error)
                except Exception as e:
                    error = str(e) + '\n' + traceback.format_exc()
                    self.respond(500, None, error)
                
                if wantsShutdown:
                    server.shutdown()
                
                break
        else:
            self.respond(404, None, "Unknown endpoint: " + self.path)
    
    def respond(self, status, data, error=None):
        response = {"data": data}
        if error:
            response["error"] = error
        
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, default=lambda o: '').encode("utf-8"))
            


if __name__ == "__main__":

    # Create server with first available port
    server = HTTPServer(("", 0), RequestHandler)
    
    # Notify extension of our port
    myPort = server.server_address[1]
    callback = http.client.HTTPConnection('localhost', int(os.environ["EXT_PORT"]))
    headers = {'Content-type': 'application/json'}
    body = json.dumps({'port': myPort})
    callback.request('POST', '/tweakstudio/ida', body, headers)

    # Begin serving requests
    try:
        # while continueServing:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
