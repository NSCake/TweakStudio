#
#  endpoints.py
#  Tweak Studio
#  
#  Created by Tanner Bennett on 2021-06-22
#  Copyright (c) 2021 Tanner Bennett. All rights reserved.
#

from globals import EditorAction, triggerShutdown
import ida_helpers as ida
from ida_hexrays import *
from idautils import *
from idaapi import *
from idc import *
import sark

kEndpoints = []

def Endpoint(cls):
    global kEndpoints
    kEndpoints.append(cls)
    return cls

@Endpoint
class Shutdown:
    PATH = "/shutdown"

    @classmethod
    def run(cls, save):
        triggerShutdown()
        save_database('', 0 if save else DBFL_KILL | DBFL_TEMP)
        return {}

@Endpoint
class Save:
    PATH = "/save"
    
    @classmethod
    def run(cls, outfile):
        save_database(outfile.encode("utf-8") if outfile else '', 0)
        return {}

@Endpoint
class ListSegments:
    PATH = "/segments"

    @classmethod
    def run(cls):
        return [segment.name for segment in sark.segments()]

@Endpoint
class ListProcedures:
    PATH = "/procedures"

    @classmethod
    def run(cls, segment_name):
        if not segment_name:
            # Map each segment name to a list of procedures
            allProcs = map(cls.procsForSegment, ListSegments.run())
            # Flatten each list
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

@Endpoint
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

@Endpoint
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
                    lineno, data = ida.pscDataForAddress(ref)
                    # Store only one ref for each line number
                    if data and not lineno in results:
                        # Only store if line content contains the selector
                        lineContent = data['lineContent']
                        if line.bytes[0:-1] in lineContent:
                            results[lineno] = data
                        # TODO: return all matches in another part of the response
                
                return results.values()
        
        # Probably not a selector, or has no references
        return []
                    
@Endpoint
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
            lineno, data = ida.pscDataForAddress(ref)
            # Store first ref for each line number
            if data and not lineno in results:
                results[lineno] = data
        
        return results.values()

@Endpoint
class SymbolForAddress:
    PATH = "/symbolicate"
    
    @classmethod
    def run(cls, addr):
        line = sark.Line(ea=addr)
        if line:
            return line.name
        
        return None

@Endpoint
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

@Endpoint
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

@Endpoint
class ExprTypeUnderCursor:
    PATH = "/expr_at_pos"
    
    @classmethod
    def run(cls, addr, line, col):
        cfunc, psc = ida.decomp(addr)
        idx = ida.citem_by_pos(psc, line, col)
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

@Endpoint
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

@Endpoint
class PerformEditorAction:
    PATH = "/editor_action"
    
    @classmethod
    def run(cls, action, args):
        if not action:
            return None
        
        if action == EditorAction.addComment:
            funcAddr = args['funcAddr']
            lineno = args['line']
            comment = args['comment']
            
            # Cannot comment function itself
            if lineno == 0:
                return False
            
            cfunc, linesToCItems, _, _ = ida.citemData(funcAddr)
            
            lineItems = linesToCItems[lineno]
            if lineItems.count > 0: # Some lines have no tree items
                lastCItemIdx = lineItems.pop()
                lineEA = cfunc.treeitems[lastCItemIdx].ea
                
                return ida.create_comment(cfunc, lineEA, comment.encode("utf-8"))
            
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

@Endpoint
class dbg_LineData:
    PATH = "/line_data"
    
    @classmethod
    def run(cls, addr, line):
        cfunc, psc = ida.decomp(addr)
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
