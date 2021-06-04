#
#  disam.py
#  Tweak Studio
#  
#  Created by Tanner Bennett on 2021-06-03
#  Copyright © 2021 Tanner Bennett. All rights reserved.
#

from ida_hexrays import *
from idaapi import *

import idaapi
class disam(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Disassembler helper"
    wanted_hotkey = "Alt-F8"
    def init(self):
        # idaapi.msg("init() called!\n")
        return idaapi.PLUGIN_OK
    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)
    def term(self):
        idaapi.msg("term() called!\n")
def PLUGIN_ENTRY():
    return disam()
