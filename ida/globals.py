#
#  globals.py
#  Tweak Studio
#  
#  Created by Tanner Bennett on 2021-06-22
#  Copyright (c) 2021 Tanner Bennett. All rights reserved.
#

from enum import IntEnum

class EditorAction(IntEnum):
    renameVar = 1,
    renameSymbol = 2,
    listXrefs = 3,
    addComment = 4,
    clearComment = 5,
    addVArg = 6,
    removeVArg = 7,

_wantsShutdown = False

def triggerShutdown():
    global _wantsShutdown
    _wantsShutdown = True

def wantsShutdown():
    global _wantsShutdown
    return _wantsShutdown
