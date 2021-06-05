#
#  ida/proxy.py
#  Tweak Studio
#
#  Created by Tanner Bennett on 2021-05-24
#  Originated from file created by Ethan Arbuckle on 2021-03-05
#  Copyright (c) 2021 Ethan Arbuckle and Tanner Bennett. All rights reserved.
#

import json
import traceback
import http.client
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from ida_hexrays import *
from idautils import *
from idaapi import *
from idc import *
import sark

import itertools
import types

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
                    "label": function.demangled,
                    "address": function.startEA,
                    "segment": segment_name,
                }
            )

        return named_procedures


class ListStrings:
    PATH = "/strings"

    @classmethod
    def run(cls):
        seg = sark.Segment(name="__cstring")
        
        strings = []
        for line in seg.lines:
            if line.is_string:
                strings.append(
                    {
                        "label": line.name or line.bytes,
                        "address": line.startEA,
                        "segment": "__cstring",
                    }
                )
        
        seg = sark.Segment(name="__cfstring")
        
        for line in seg.lines:
            if line.is_string:
                strings.append(
                    {
                        "label": line.name or line.bytes,
                        "address": line.startEA,
                        "segment": "__cfstring",
                    }
                )
                
        return strings


class DecompileProcedure:
    PATH = "/decompile"

    @classmethod
    def run(cls, procedure_address):
        # if not init_hexrays_plugin(PLUGIN_PROC):
        #     raise Exception("Plugin or script not compatible with decompiler")
            
        if not procedure_address:
            raise Exception("did not specify procedure address")

        proc_name = idc.get_func_name(procedure_address)
        procedure_candidate = sark.Function(ea=procedure_address)
        
        if procedure_candidate:
            lines = []
            cfunc = decompile(procedure_address)
            pscode = cfuncptr_t.get_pseudocode(cfunc)
            for line in pscode:
                lines.append(tag_remove(line.line))
                
            return "\n".join(lines)

        raise Exception("Failed to find the specified procedure")


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
            DecompileProcedure,
            ListStrings,
            DisassembleProcedure,
        ]:
            if self.path == handler.PATH:
                try:
                    data_response = handler.run(**posted_data)
                    self.send_response(200)
                except TypeError as e:
                    self.send_response(500)
                    error = str(e) + '\n' + traceback.format_exc()
                except Exception as e:
                    self.send_response(500)
                    error = str(e) + '\n' + traceback.format_exc()

                response = {"data": data_response}
                if error:
                    response["error"] = error

                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response, default=lambda o: '').encode("utf-8"))
                
                if wantsShutdown:
                    server.shutdown()


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
