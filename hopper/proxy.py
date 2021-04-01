#
#  hopper_proxy.py
#  Tweak Studio
#
#  Created by Ethan Arbuckle on 2021-03-05
#  Copyright (c) 2021 Ethan Arbuckle and Tanner Bennett. All rights reserved.
#

import json
import subprocess
import typing
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

if typing.TYPE_CHECKING:
    from hopper_api import Document


class TerminateHopper:
    PATH = "/terminate"

    @classmethod
    def kill_hopper(cls):
        """Kill all running Hopper processes"""
        ps_output = subprocess.check_output(["ps", "aux"]).decode("utf-8")
        for ps_line in ps_output.splitlines():
            # Look for Hopper
            if "Hopper" in ps_line:
                components = ps_line.split(" ")
                # PID is the first number
                pid = [component for component in components if component.isnumeric()][0]
                # Terminate it
                subprocess.check_output(["kill", pid])

    @classmethod
    def run(cls):
        TerminateHopper.kill_hopper()
        pass


class ListSegments:
    PATH = "/segments"

    @classmethod
    def run(cls):
        segments = Document.getCurrentDocument().getSegmentsList()
        return [segment.getName() for segment in segments]


class ListProcedures:
    PATH = "/procedures"

    @classmethod
    def run(cls):

        named_procedures = []
        for segment_name in ListSegments.run():
            segment = Document.getCurrentDocument().getSegmentByName(segment_name)
            for label_address in segment.getNamedAddresses():
                named_procedures.append(
                    {
                        "label": segment.getDemangledNameAtAddress(label_address),
                        "address": label_address,
                    }
                )

        return named_procedures


class ListStrings:
    PATH = "/strings"

    @classmethod
    def run(cls):
        doc = Document.getCurrentDocument()
        cstrings_sect = doc.getSectionByName("__cstring")
        text_seg = doc.getSegmentByName("__TEXT")
        cstring_start = cstrings_sect.getStartingAddress()

        string_cursor = 0
        strings = []
        while string_cursor < cstrings_sect.getLength():
            stringlen = text_seg.getObjectLength(cstring_start + string_cursor)
            string = text_seg.readBytes(cstring_start + string_cursor, stringlen - 1).strip()
            string_cursor += max(stringlen, 1)
            strings.append(string)
        return strings


class DecompileProcedure:
    PATH = "/decompile"

    @classmethod
    def run(cls, procedure_address):
        if not procedure_address:
            raise Exception("did not specify procedure address")

        # Hopper's API requires you to know the segment that contains a procedure (even though procs are
        # referenced by their absolute address in the binary).
        # Try all known segments
        for segment_name in ListSegments.run():
            segment = Document.getCurrentDocument().getSegmentByName(segment_name)
            procedure_candidate = segment.getProcedureAtAddress(procedure_address)
            if procedure_candidate:
                return procedure_candidate.decompile()

        raise Exception("Failed to find the specified procedure")


class DisassembleProcedure:
    PATH = "/disassemble"

    @classmethod
    def run(cls, procedure_address):
        if not procedure_address:
            raise Exception("did not specify procedure address")

        disassembly = ""

        # Hopper's API requires you to know the segment that contains a procedure (even though procs are
        # referenced by their absolute address in the binary).
        # Try all known segments
        for segment_name in ListSegments.run():
            segment = Document.getCurrentDocument().getSegmentByName(segment_name)
            procedure_candidate = segment.getProcedureAtAddress(procedure_address)
            if procedure_candidate:

                for basic_block in procedure_candidate.basicBlockIterator():
                    basic_block_start = basic_block.getStartingAddress()
                    instr_cursor = basic_block_start
                    while instr_cursor < basic_block.getEndingAddress():
                        instr = segment.getInstructionAtAddress(instr_cursor)
                        instr_args = [instr.getFormattedArgument(i) for i in xrange(instr.getArgumentCount())]

                        instr_string = instr.getInstructionString() + "  "
                        instr_string += ", ".join(instr_args)
                        instr_string += "\n"
                        disassembly += instr_string

                        instr_cursor += instr.getInstructionLength()
        # Maybe this should return a list of instructions, instead of combining them into 1 string?
        return disassembly


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        posted_data = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        data_response = None
        error = None

        for handler in [ListSegments, ListProcedures, DecompileProcedure, TerminateHopper, ListStrings, DisassembleProcedure]:
            if self.path == handler.PATH:

                try:
                    data_response = handler.run(**posted_data)
                    json.dumps(data_response)
                    self.send_response(200)
                except TypeError as e:
                    self.send_response(500)
                    error = str(e)
                except Exception as e:
                    self.send_response(500)
                    error = str(e)

                response = {"data": data_response}
                if error:
                    response["error"] = error

                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))


if __name__ == "__main__":

    httpd = HTTPServer(("", 52349), RequestHandler)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
