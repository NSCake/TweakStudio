"""<p>Here are all the public classes, and methods that you can use to script Hopper using Python."""
"""</p>"""
"""<p>Before using the scripting capabilities of Hopper, you need to understand the nature of a Hopper document."""
"""The basic concept is that it is a document constructed from Segments, each containing Sections of typed bytes."""
"""Let's consider a standard Mach-O file. It contains at least one segment of code (usually named TEXT)"""
"""containing many bytes. Hopper attaches information to each bytes of each segments. At load time, all"""
"""bytes are set to the type <b>TYPE_UNDEFINED</b>. Then, starting from the entry point, as Hopper follows the program flow it will set"""
"""instructions to the type <b>TYPE_CODE</b>; if an instruction needs more than one byte, the following are set to <b>TYPE_NEXT</b>."""
"""</p>"""
"""<p>Using Python, you'll can manipulate the segments of disassembled files, retrieve information on bytes types, read or write data,"""
"""create or modify label names, etc..."""
"""You'll usually start by retrieving the current document, using the static method <b>Document.getCurrentDocument()</b>.<br/>"""
"""</p>"""
"""<hr/>"""

import HopperLowLevel
import struct

class HopperStdRedirection: # NO_DOC
    def __init__(self,tag):
        self.tag = tag
        self.line_buffer = ""

    def __del__(self):
        if (len(self.line_buffer)):
            HopperLowLevel.outputString(self.tag, self.line_buffer)
            self.line_buffer = ""

    def flushLines(self):
        idx = self.line_buffer.find('\n')
        while idx != -1:
            flushed = self.line_buffer[:idx]
            self.line_buffer = self.line_buffer[idx+1:]
            HopperLowLevel.outputString(self.tag,flushed)
            idx = self.line_buffer.find('\n')

    def flush(self):
        self.flushLines()

    def write(self,str):
        self.line_buffer += str
        self.flushLines()

class CallReference:
    """An object representing a call inside from / to a procedure."""
    
    CALL_NONE = 0
    CALL_UNKNOWN = 1
    CALL_DIRECT = 2
    CALL_OBJC = 3

    def __init__(self,callType,fromAddress,toAddress):
        self.__type__ = callType
        self.__from__ = fromAddress
        self.__to__ = toAddress
    def type(self):
        """Returns the type of call. This is one of the value CALL_NONE, CALL_UNKNOWN, CALL_DIRECT, or CALL_OBJC."""
        return self.__type__
    def fromAddress(self):
        """Source of the reference"""
        return self.__from__
    def toAddress(self):
        """Referenced address"""
        return self.__to__

class LocalVariable:
    """A procedure's local variable."""
    def __init__(self,name,displacement):
        self.__name__ = name
        self.__displacement__ = displacement
    def name(self):
        """Name of the local variable"""
        return self.__name__
    def displacement(self):
        """Displacement on the stack"""
        return self.__displacement__

class Tag:
    """A Tag that could be applied to a specific address, a BasicBlock or a Procedure."""
    """Tags are built using the document."""
    def __init__(self,tag_internal):
        self.__tag_internal__ = tag_internal
    def __eq__(self,other):
        return other.__class__ == self.__class__ and self.__tag_internal__ == other.__tag_internal__
    def __ne__(self,other):
        return other.__class__ != self.__class__ or self.__tag_internal__ != other.__tag_internal__
    def getName(self):
        """Returns a string with the tag name."""
        return HopperLowLevel.getTagName(self.__tag_internal__)

class Procedure:
    """This class represents a procedure, which is a collection of BasicBlocks."""
    """Please note that modifying the document (creating new procedure, or deleting an existing one), will result in a possible"""
    """inconsistancy of the Python's Procedure object representation.<br/>"""
    """Procedure class defines some constants:<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_GENERAL_PURPOSE_REGISTER</b> = 2<br/>"""
    """<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_FPU</b>     =  3<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_MMX</b>     =  4<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_SSE</b>     =  5<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_AVX</b>     =  6<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_CR</b>      =  7<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_DR</b>      =  8<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_SPECIAL</b> =  9<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_MEMMGMT</b> = 10<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_X86_SEG</b>     = 11<br/>"""
    """<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_ARM_VFP_SINGLE</b> = 3<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_ARM_VFP_DOUBLE</b> = 4<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_ARM_VFP_QUAD</b>   = 5<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_ARM_MEDIA</b>      = 6<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGCLS_ARM_SPECIAL</b>    = 7<br/>"""
    """<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RAX</b> =  0<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RCX</b> =  1<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RDX</b> =  2<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RBX</b> =  3<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RSP</b> =  4<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RBP</b> =  5<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RSI</b> =  6<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RDI</b> =  7<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R8</b>  =  8<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R9</b>  =  9<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R10</b> = 10<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R11</b> = 11<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R12</b> = 12<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R13</b> = 13<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R14</b> = 14<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_R15</b> = 15<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>REGIDX_X86_RIP</b> = 16<br/>"""
    
    REGCLS_GENERAL_PURPOSE_REGISTER = 2

    REGCLS_X86_FPU     = 3
    REGCLS_X86_MMX     = 4
    REGCLS_X86_SSE     = 5
    REGCLS_X86_AVX     = 6
    REGCLS_X86_CR      = 7
    REGCLS_X86_DR      = 8
    REGCLS_X86_SPECIAL = 9
    REGCLS_X86_MEMMGMT = 10
    REGCLS_X86_SEG     = 11

    REGCLS_ARM_VFP_SINGLE = 3
    REGCLS_ARM_VFP_DOUBLE = 4
    REGCLS_ARM_VFP_QUAD   = 5
    REGCLS_ARM_MEDIA      = 6
    REGCLS_ARM_SPECIAL    = 7

    REGIDX_X86_RAX =  0
    REGIDX_X86_RCX =  1
    REGIDX_X86_RDX =  2
    REGIDX_X86_RBX =  3
    REGIDX_X86_RSP =  4
    REGIDX_X86_RBP =  5
    REGIDX_X86_RSI =  6
    REGIDX_X86_RDI =  7
    REGIDX_X86_R8  =  8
    REGIDX_X86_R9  =  9
    REGIDX_X86_R10 = 10
    REGIDX_X86_R11 = 11
    REGIDX_X86_R12 = 12
    REGIDX_X86_R13 = 13
    REGIDX_X86_R14 = 14
    REGIDX_X86_R15 = 15
    REGIDX_X86_RIP = 16

    def __init__(self,segment_internal,procedure_index):
        self.__segment_internal__ = segment_internal
        self.__procedure_index__ = procedure_index
    def __eq__(self,other):
        return other.__class__ == self.__class__ and self.__segment_internal__ == other.__segment_internal__ and self.__procedure_index__ == other.__procedure_index__
    def __ne__(self,other):
        return other.__class__ != self.__class__ or self.__segment_internal__ != other.__segment_internal__ or self.__procedure_index__ != other.__procedure_index__
    def getSegment(self):
        """Returns the segment this procedure belongs to."""
        return Segment(self.__segment_internal__)
    def getSection(self):
        """Returns the section this procedure belongs to."""
        return self.getSegment().getSectionAtAddress(self.getEntryPoint())
    def getEntryPoint(self):
        """Returns the address of the entry point."""
        return HopperLowLevel.getProcedureEntryPoint(self.__segment_internal__,self.__procedure_index__)
    def getBasicBlockCount(self):
        """Returns the total number of basic blocks."""
        return HopperLowLevel.getBasicBlockCount(self.__segment_internal__,self.__procedure_index__)
    def getBasicBlock(self,index):
        """Get a BasicBlock object by index."""
        return BasicBlock(self,index) if index >= 0 and index < self.getBasicBlockCount() else None
    def getBasicBlockAtAddress(self,addr):
        """Returns the basic block which contains an instruction starting at the given address, or None."""
        index = HopperLowLevel.getBasicBlockIndexAtAddress(self.__segment_internal__,self.__procedure_index__,addr)
        return BasicBlock(self,index) if index >= 0 and index < self.getBasicBlockCount() else None
    def basicBlockIterator(self):
        """Iterate over all basic blocks of the procedure"""
        for index in xrange(self.getBasicBlockCount()):
            yield self.getBasicBlock(index)
    def getHeapSize(self):
        """Returns the heap size of the procedure in bytes."""
        return HopperLowLevel.getProcedureHeapSize(self.__segment_internal__,self.__procedure_index__)
    def getLocalVariableList(self):
        """Returns the list of all local variables."""
        return HopperLowLevel.getLocalVariableList(self.__segment_internal__,self.__procedure_index__)
    def addTag(self,tag):
        """Add a tag to the procedure."""
        HopperLowLevel.addTagToProcedure(self.__segment_internal__,self.__procedure_index__,tag.__tag_internal__)
    def removeTag(self,tag):
        """Remove the tag from the procedure."""
        HopperLowLevel.removeTagFromProcedure(self.__segment_internal__,self.__procedure_index__,tag.__tag_internal__)
    def hasTag(self,tag):
        """Returns True if the procedure has this tag."""
        return HopperLowLevel.procedureHasTag(self.__segment_internal__,self.__procedure_index__,tag.__tag_internal__)
    def getTagCount(self):
        """Returns the number of tags for this procedure."""
        return HopperLowLevel.getProcedureTagCount(self.__segment_internal__,self.__procedure_index__)
    def getTagAtIndex(self,index):
        """Returns the Nth tag of the procedure."""
        tag_ptr = HopperLowLevel.getProcedureTagAtIndex(self.__segment_internal__,self.__procedure_index__,index)
        return Tag(tag_ptr) if tag_ptr != 0 else None
    def tagIterator(self):
        """Iterate over all tags of the procedure"""
        for index in xrange(self.getTagCount()):
            yield self.getTagAtIndex(index)
    def getTagList(self):
        """Returns a list a all tags for this procedure."""
        return [tag for tag in self.tagIterator()]
    def getAllCallers(self):
        """Returns a list of CallReference objects representing callers of this procedure."""
        return HopperLowLevel.getAllCallers(self.__segment_internal__,self.__procedure_index__)
    def getAllCallees(self):
        """Returns a list of CallReference objects representing all the places called by this procedure."""
        return HopperLowLevel.getAllCallees(self.__segment_internal__,self.__procedure_index__)
    def getAllCallerProcedures(self):
        """Returns a list of Procedure objects representing callers of this procedure."""
        return HopperLowLevel.getAllCallerProcedures(self.__segment_internal__,self.__procedure_index__)
    def getAllCalleeProcedures(self):
        """Returns a list of CallReference objects representing all the procedures called by this procedure."""
        return HopperLowLevel.getAllCalleeProcedures(self.__segment_internal__,self.__procedure_index__)
    def hasLocalLabelAtAddress(self,addr):
        """Return True if there is a local label at a given address."""
        return HopperLowLevel.hasLocalLabelAtAddress(self.__segment_internal__,self.__procedure_index__,addr)
    def localLabelAtAddress(self,addr):
        """Return the local label name at a given address, or None if there is no label at this address."""
        return HopperLowLevel.localLabelAtAddress(self.__segment_internal__,self.__procedure_index__,addr)
    def setLocalLabelAtAddress(self,label,addr):
        """Set the local label for a given address."""
        return HopperLowLevel.setLocalLabelAtAddress(self.__segment_internal__,self.__procedure_index__,label,addr)
    def declareLocalLabelAt(self,addr):
        """Create a local label at a given address, and return its name."""
        return HopperLowLevel.declareLocalLabelAt(self.__segment_internal__,self.__procedure_index__,addr)
    def removeLocalLabelAtAddress(self,addr):
        """Remove a local label."""
        return HopperLowLevel.removeLocalLabelAtAddress(self.__segment_internal__,self.__procedure_index__,addr)
    def addressOfLocalLabel(self,label):
        """Return the address of the local label."""
        return HopperLowLevel.addressOfLocalLabel(self.__segment_internal__,self.__procedure_index__,label)
    def decompile(self):
        """Returns a string containing the pseudo-code of the procedure, or None if the decompilation is not possible."""
        return HopperLowLevel.decompile(self.__segment_internal__,self.__procedure_index__)
    def signatureString(self):
        """Returns a string containing the signature of the procedure."""
        return HopperLowLevel.procedureSignature(self.__segment_internal__,self.__procedure_index__)
    def renameRegister(self,reg_cls,reg_idx,name):
        """Rename the register reg_idx, of class reg_cls to the provided name. The reg_cls argument is one of the REGCLS_* constants."""
        return HopperLowLevel.renameRegister(self.__segment_internal__,self.__procedure_index__,reg_cls,reg_idx,name)
    def registerNameOverride(self,reg_cls,reg_idx):
        """Returns the name given to the register, if it has been previously renamed. Otherwise, returns None. The reg_cls argument is one of the REGCLS_* constants."""
        return HopperLowLevel.registerNameOverride(self.__segment_internal__,self.__procedure_index__,reg_cls,reg_idx)
    def clearRegisterNameOverride(self,reg_cls,reg_idx):
        """Clear register renaming. The reg_cls argument is one of the REGCLS_* constants."""
        return HopperLowLevel.clearRegisterNameOverride(self.__segment_internal__,self.__procedure_index__,reg_cls,reg_idx)

class BasicBlock:
    """A BasicBlock is a set of instructions that is guaranteed to be executed in a whole, if the control flow reach the first instruction."""
    def __init__(self,procedure,basic_block_index):
        self.__procedure__ = procedure
        self.__basic_block_index__ = basic_block_index
    def __eq__(self,other):
        return other.__class__ == self.__class__ and self.__procedure__ == other.__procedure__ and self.__basic_block_index__ == other.__basic_block_index__
    def __ne__(self,other):
        return other.__class__ != self.__class__ or self.__procedure__ != other.__procedure__ or self.__basic_block_index__ != other.__basic_block_index__
    def getProcedure(self):
        """Returns the Procedure object this BasicBlock belongs to."""
        return self.__procedure__
    def getStartingAddress(self):
        """Returns the address of the first instruction of the BasicBlock."""
        return HopperLowLevel.getBasicBlockStartingAddress(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__)
    def getEndingAddress(self):
        """Returns the address following the last instruction of the BasicBlock."""
        return HopperLowLevel.getBasicBlockEndingAddress(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__)
    def getSuccessorCount(self):
        """Returns the number of successors for this BasicBlock."""
        return HopperLowLevel.getBasicBlockSuccessorCount(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__)
    def getSuccessorIndexAtIndex(self,index):
        """Returns the BasicBlock index of the Nth successors."""
        return HopperLowLevel.getBasicBlockSuccessorIndex(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__,index)
    def getSuccessorAddressAtIndex(self,index):
        """Returns the BasicBlock address of the Nth successors."""
        return HopperLowLevel.getBasicBlockSuccessorAddress(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__,index)
    def addTag(self,tag):
        """Add a tag to the basic block."""
        HopperLowLevel.addTagToBasicBlock(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__,tag.__tag_internal__)
    def removeTag(self,tag):
        """Remove the tag from the basic block."""
        HopperLowLevel.removeTagFromBasicBlock(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__,tag.__tag_internal__)
    def hasTag(self,tag):
        """Returns True if the basic block has this tag."""
        return HopperLowLevel.basicBlockHasTag(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__,tag.__tag_internal__)
    def getTagCount(self):
        """Return the number of tags for this basic block."""
        return HopperLowLevel.getBasicBlockTagCount(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__)
    def getTagAtIndex(self,index):
        """Return the Nth tag of the basic block."""
        tag_ptr = HopperLowLevel.getBasicBlockTagAtIndex(self.__procedure__.__segment_internal__,self.__procedure__.__procedure_index__,self.__basic_block_index__,index)
        return Tag(tag_ptr) if tag_ptr != 0 else None
    def tagIterator(self):
        """Iterate over all tags of the basic block"""
        for index in xrange(self.getTagCount()):
            yield self.getTagAtIndex(index)
    def getTagList(self):
        """Return a list a all tags for this basic block."""
        return [tag for tag in self.tagIterator()]

class Instruction:
    """This class represents a disassembled instruction."""
    """The class defines some constants, like <b>ARCHITECTURE_i386</b>, and <b>ARCHITECTURE_X86_64</b>"""

    ARCHITECTURE_UNKNOWN = 0
    ARCHITECTURE_i386 = 1
    ARCHITECTURE_X86_64 = 2
    ARCHITECTURE_ARM = 3
    ARCHITECTURE_ARM_THUMB = 4,
    ARCHITECTURE_AARCH64 = 5,
    ARCHITECTURE_OTHER = 99

    def __init__(self,archi,instr,rawArgs,formattedArgs,cjmp,ijmp,instrLen):
        self.__archi__ = archi
        self.__instr__ = instr
        self.__rawArgs__ = rawArgs
        self.__formattedArgs__ = formattedArgs
        self.__cjmp__ = cjmp
        self.__ijmp__ = ijmp
        self.__instrLen__ = instrLen

    @staticmethod
    def stringForArchitecture(t):
        """Helper method which converts one of the architecture value (<b>ARCHITECTURE_UNKNOWN</b>, <b>ARCHITECTURE_i386</b>, <b>ARCHITECTURE_X86_64</b>, <b>ARCHITECTURE_ARM</b>, <b>ARCHITECTURE_ARM_THUMB</b>, or  <b>ARCHITECTURE_AARCH64</b>) to a string value."""
        return {
        Instruction.ARCHITECTURE_UNKNOWN : "unknown",
        Instruction.ARCHITECTURE_i386 : "i386",
        Instruction.ARCHITECTURE_X86_64 : "x86_64",
        Instruction.ARCHITECTURE_ARM : "ARM",
        Instruction.ARCHITECTURE_ARM_THUMB : "ARM (Thumb)",
        Instruction.ARCHITECTURE_AARCH64 : "AArch64",
        Instruction.ARCHITECTURE_OTHER : "Other (plugin)"
        }.get(t, "<unknown>")

    def getArchitecture(self):
        """Returns the architecture."""
        return self.__archi__

    def getInstructionString(self):
        """Return a strings representing the instruction."""
        return self.__instr__

    def getArgumentCount(self):
        """Returns the number of argument."""
        return len(self.__rawArgs__)

    def getRawArgument(self,index):
        """Returns the instruction argument, identified by an index. The argument is not modified by Hopper, and represents the raw ASM argument."""
        if index < 0 or index >= len(self.__rawArgs__):
            return None
        return self.__rawArgs__[index]

    def getFormattedArgument(self,index):
        """Returns the instruction argument, identified by an index. The argument may have been modified according to the user, or by Hopper if"""
        """ a specific pattern has been detected."""
        if index < 0 or index >= len(self.__formattedArgs__):
            return None
        return self.__formattedArgs__[index]

    def isAnInconditionalJump(self):
        """Returns True if the instruction represents an inconditional jump."""
        return self.__ijmp__

    def isAConditionalJump(self):
        """Returns True if the instruction represents a conditional jump."""
        return self.__cjmp__

    def getInstructionLength(self):
        """Returns the instruction length in byte."""
        return self.__instrLen__

class Section:
    """This class represents a section of a segment."""
    def __init__(self,addr):
        self.__internal_section_addr__ = addr
    def __eq__(self,other):
        return other.__class__ == self.__class__  and self.__internal_section_addr__ == other.__internal_section_addr__
    def __ne__(self,other):
        return other.__class__ != self.__class__ or self.__internal_section_addr__ != other.__internal_section_addr__
    def getName(self):
        """Returns the name of the section."""
        return HopperLowLevel.getSectionName(self.__internal_section_addr__)
    def getStartingAddress(self):
        """Returns the starting address of the section."""
        return HopperLowLevel.getSectionStartingAddress(self.__internal_section_addr__)
    def getLength(self):
        """Returns the length, in bytes, of the section."""
        return HopperLowLevel.getSectionLength(self.__internal_section_addr__)
    def getFlags(self):
        """Returns the flags of the section."""
        return HopperLowLevel.getSectionFlags(self.__internal_section_addr__)

class Segment:
    """This class represents a segment of a disassembled file."""
    """The class defines some values that are used as the type"""
    """of bytes of the disassembled file.<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_UNDEFINED</b> : an undefined byte<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_OUTSIDE</b> : the byte is not in a mapped section<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_NEXT</b> : a byte that is part of a larger data type (ex, the second byte of a 4 bytes integer...)<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_INT8</b> : an integer of a single byte<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_INT16</b> : an integer of 2 bytes<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_INT32</b> : an integer of 4 bytes<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_INT64</b> : an integer of 8 bytes<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_ASCII</b> : an ASCII string<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_ALIGN</b> : an alignment<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_UNICODE</b> : an UNICODE string<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_CODE</b> : an instruction<br/>"""
    """&nbsp;&nbsp;&nbsp;&nbsp;<b>TYPE_PROCEDURE</b> : a procedure<br/>"""
    """<br/>"""
    """The class defines the constant <b>BAD_ADDRESS</b> which is returned by some methods when the"""
    """requested information is incorrect."""

    BAD_ADDRESS=-1

    TYPE_UNDEFINED=0
    TYPE_OUTSIDE=1
    TYPE_NEXT=2
    TYPE_INT8=3
    TYPE_INT16=4
    TYPE_INT32=5
    TYPE_INT64=6
    TYPE_ASCII=7
    TYPE_UNICODE=8
    TYPE_ALIGN=63
    TYPE_CODE=65
    TYPE_PROCEDURE=66
    TYPE_STRUCTURE=67

    @staticmethod
    def stringForType(t):
        """Helper method that converts one of the type value (<b>TYPE_UNDEFINED</b>, <b>TYPE_NEXT</b>, ...) to a string value."""
        return {
        Segment.TYPE_UNDEFINED : "undefined",
        Segment.TYPE_NEXT : "next",
        Segment.TYPE_INT8 : "int8",
        Segment.TYPE_INT16 : "int16",
        Segment.TYPE_INT32 : "int32",
        Segment.TYPE_INT64 : "int64",
        Segment.TYPE_ASCII : "ascii",
        Segment.TYPE_UNICODE : "unicode",
        Segment.TYPE_ALIGN : "align",
        Segment.TYPE_CODE : "code",
        Segment.TYPE_PROCEDURE : "procedure",
        Segment.TYPE_STRUCTURE : "structure",
        }.get(t, "<unknown>")

    def __init__(self,addr):
        self.__internal_segment_addr__ = addr
    def __eq__(self,other):
        return other.__class__ == self.__class__ and self.__internal_segment_addr__ == other.__internal_segment_addr__
    def __ne__(self,other):
        return other.__class__ != self.__class__ or self.__internal_segment_addr__ != other.__internal_segment_addr__
    def getName(self):
        """Returns the name of the segment."""
        return HopperLowLevel.getSegmentName(self.__internal_segment_addr__)
    def getStartingAddress(self):
        """Returns the starting address of the segment."""
        return HopperLowLevel.getSegmentStartingAddress(self.__internal_segment_addr__)
    def getLength(self):
        """Returns the length, in bytes, of the segment."""
        return HopperLowLevel.getSegmentLength(self.__internal_segment_addr__)
    def getFileOffset(self):
        """Returns the file offset of the beginning of the segment."""
        return HopperLowLevel.getFileOffset(self.__internal_segment_addr__)
    def getFileOffsetForAddress(self,addr):
        """Returns the file offset of a particular address."""
        return self.getFileOffset() + addr - self.getStartingAddress()
    def getSectionCount(self):
        """Returns the number of section this segment contains."""
        return HopperLowLevel.getSectionCount(self.__internal_segment_addr__);
    def getSection(self,index):
        """Returns a section by index. The returned object is an instance of the Section class. If the index of not in the range [0;count[, the function returns None."""
        addr = HopperLowLevel.getSectionAddress(self.__internal_segment_addr__, index)
        if addr == 0:
            return None
        return Section(addr)
    def getSectionsList(self):
        """Returns a list containing all the sections."""
        return [self.getSection(x) for x in xrange(self.getSectionCount())]
    def getSectionIndexAtAddress(self,addr):
        """Returns the section index for a particular address."""
        return HopperLowLevel.getSectionIndexAtAddress(self.__internal_segment_addr__,addr)
    def getSectionAtAddress(self,addr):
        """Returns the section for a particular address."""
        idx=self.getSectionIndexAtAddress(addr)
        if idx == -1:
            return None
        return self.getSection(idx)
    def readBytes(self,addr,length):
        """Read bytes at a given address range. Returns False if the byte is read outside of the segment."""
        return HopperLowLevel.readBytes(self.__internal_segment_addr__,addr,length)
    def readByte(self,addr):
        """Read a byte (between 0..255), read at a given address. Returns False if the byte is read outside of the segment."""
        result = HopperLowLevel.readBytes(self.__internal_segment_addr__,addr,1)
        if result == False:
            return False
        return struct.unpack("B", result)[0]
    def readUInt16LE(self,addr):
        """Read a 16 bits little endian integer."""
        return self.readByte(addr) | (self.readByte(addr + 1) << 8)
    def readUInt32LE(self,addr):
        """Read a 32 bits little endian integer."""
        return self.readByte(addr) | (self.readByte(addr + 1) << 8) | (self.readByte(addr + 2) << 16) | (self.readByte(addr + 3) << 24)
    def readUInt64LE(self,addr):
        """Read a 64 bits little endian integer."""
        return self.readByte(addr) | (self.readByte(addr + 1) << 8) | (self.readByte(addr + 2) << 16) | (self.readByte(addr + 3) << 24) | (self.readByte(addr + 4) << 32) | (self.readByte(addr + 5) << 40) | (self.readByte(addr + 6) << 48) | (self.readByte(addr + 7) << 56)
    def readUInt16BE(self,addr):
        """Read a 16 bits big endian integer."""
        return self.readByte(addr + 1) | (self.readByte(addr) << 8)
    def readUInt32BE(self,addr):
        """Read a 32 bits big endian integer."""
        return self.readByte(addr + 3) | (self.readByte(addr + 2) << 8) | (self.readByte(addr + 1) << 16) | (self.readByte(addr) << 24)
    def readUInt64BE(self,addr):
        """Read a 64 bits big endian integer."""
        return self.readByte(addr + 7) | (self.readByte(addr + 6) << 8) | (self.readByte(addr + 5) << 16) | (self.readByte(addr + 4) << 24) | (self.readByte(addr + 3) << 32) | (self.readByte(addr + 2) << 40) | (self.readByte(addr + 1) << 48) | (self.readByte(addr) << 56)
    def writeBytes(self,addr,bytesStr):
        """Write bytes at a given address. Bytes are given as a string. Returns True if the writting has succeed."""
        return HopperLowLevel.writeBytes(self.__internal_segment_addr__,addr,bytesStr)
    def writeByte(self,addr,value):
        """Write a byte at a given address. Returns True if the writting has succeed."""
        return HopperLowLevel.writeBytes(self.__internal_segment_addr__,addr,struct.pack("B", value))
    def writeUInt16LE(self,addr,value):
        """Write a 16 bits little endian integer. Returns True if succeeded."""
        return self.writeByte(addr, value & 0xFF) and self.writeByte(addr + 1, (value >> 8) & 0xFF)
    def writeUInt32LE(self,addr,value):
        """Write a 32 bits little endian integer. Returns True if succeeded."""
        return self.writeByte(addr, value & 0xFF) and self.writeByte(addr + 1, (value >> 8) & 0xFF) and self.writeByte(addr + 2, (value >> 16) & 0xFF) and self.writeByte(addr + 3, (value >> 24) & 0xFF)
    def writeUInt64LE(self,addr,value):
        """Write a 32 bits little endian integer. Returns True if succeeded."""
        return self.writeByte(addr, value & 0xFF) and self.writeByte(addr + 1, (value >> 8) & 0xFF) and self.writeByte(addr + 2, (value >> 16) & 0xFF) and self.writeByte(addr + 3, (value >> 24) & 0xFF) and self.writeByte(addr + 4, (value >> 32) & 0xFF) and self.writeByte(addr + 5, (value >> 40) & 0xFF) and self.writeByte(addr + 6, (value >> 48) & 0xFF) and self.writeByte(addr + 7, (value >> 56) & 0xFF)
    def writeUInt16BE(self,addr,value):
        """Write a 16 bits big endian integer. Returns True if succeeded."""
        return self.writeByte(addr + 1, value & 0xFF) and self.writeByte(addr, (value >> 8) & 0xFF)
    def writeUInt32BE(self,addr,value):
        """Write a 32 bits big endian integer. Returns True if succeeded."""
        return self.writeByte(addr + 3, value & 0xFF) and self.writeByte(addr + 2, (value >> 8) & 0xFF) and self.writeByte(addr + 1, (value >> 16) & 0xFF) and self.writeByte(addr, (value >> 24) & 0xFF)
    def writeUInt64BE(self,addr,value):
        """Write a 32 bits big endian integer. Returns True if succeeded."""
        return self.writeByte(addr + 7, value & 0xFF) and self.writeByte(addr + 6, (value >> 8) & 0xFF) and self.writeByte(addr + 5, (value >> 16) & 0xFF) and self.writeByte(addr + 4, (value >> 24) & 0xFF) and self.writeByte(addr + 3, (value >> 32) & 0xFF) and self.writeByte(addr + 2, (value >> 40) & 0xFF) and self.writeByte(addr + 1, (value >> 48) & 0xFF) and self.writeByte(addr, (value >> 56) & 0xFF)
    def markAsUndefined(self,addr):
        """Mark the address as being undefined."""
        return HopperLowLevel.markAsUndefined(self.__internal_segment_addr__,addr)
    def markRangeAsUndefined(self,addr,length):
        """Mark the address range as being undefined."""
        return HopperLowLevel.markRangeAsUndefined(self.__internal_segment_addr__,addr,length)
    def markAsCode(self,addr):
        """Mark the address as being code."""
        return HopperLowLevel.markAsCode(self.__internal_segment_addr__,addr)
    def markAsProcedure(self,addr):
        """Mark the address as being a procedure."""
        return HopperLowLevel.markAsProcedure(self.__internal_segment_addr__,addr)
    def markAsDataByteArray(self,addr,count):
        """Mark the address as being byte array."""
        return HopperLowLevel.markAsDataByteArray(self.__internal_segment_addr__,addr,count)
    def markAsDataShortArray(self,addr,count):
        """Mark the address as being a short array."""
        return HopperLowLevel.markAsDataShortArray(self.__internal_segment_addr__,addr,count)
    def markAsDataIntArray(self,addr,count):
        """Mark the address as being an int array."""
        return HopperLowLevel.markAsDataIntArray(self.__internal_segment_addr__,addr,count)
    def isThumbAtAddress(self,addr):
        """Returns True is instruction at address addr is ARM Thumb mode."""
        return HopperLowLevel.isThumbAtAddress(self.__internal_segment_addr__,addr)
    def setThumbModeAtAddress(self,addr):
        """Set the Thumb mode at the given address."""
        return HopperLowLevel.setThumbModeAtAddress(self.__internal_segment_addr__,addr)
    def setARMModeAtAddress(self,addr):
        """Set the ARM mode at the given address."""
        return HopperLowLevel.setARMModeAtAddress(self.__internal_segment_addr__,addr)
    def getTypeAtAddress(self,addr):
        """Returns the type of the byte at a given address."""
        """The type can be <b>TYPE_UNDEFINED</b>, <b>TYPE_NEXT</b>, <b>TYPE_INT8</b>, ..."""
        """The method will returns None if the address is outside the segment."""
        return HopperLowLevel.getTypeAtAddress(self.__internal_segment_addr__,addr)
    def setTypeAtAddress(self,addr,length,typeValue):
        """Set the type of a byte range."""
        """The type must be <b>TYPE_UNDEFINED</b>, <b>TYPE_INT8</b>, ..."""
        return HopperLowLevel.setTypeAtAddress(self.__internal_segment_addr__,addr,length,typeValue)
    def getNextAddressWithType(self,addr,typeValue):
        """Returns the next address of a given type."""
        """The search begins at the given address, so the returned value can be the given address itself."""
        """If no address are found, the returned value is <b>BAD_ADDRESS</b>."""
        return HopperLowLevel.getNextAddressWithType(self.__internal_segment_addr__,addr,typeValue)
    def disassembleWholeSegment(self):
        """Disassemble the whole segment."""
        return HopperLowLevel.disassembleWholeSegment(self.__internal_segment_addr__)
    def setNameAtAddress(self,addr,name):
        """Set the label name at a given address."""
        return (HopperLowLevel.setNameAtAddress(self.__internal_segment_addr__,addr,name) == 1)
    def getNameAtAddress(self,addr):
        """Get the label name at a given address."""
        return HopperLowLevel.getNameAtAddress(self.__internal_segment_addr__,addr)
    def getDemangledNameAtAddress(self,addr):
        """Get the demangled label name at a given address."""
        return HopperLowLevel.getDemangledNameAtAddress(self.__internal_segment_addr__,addr)
    def getCommentAtAddress(self,addr):
        """Get the prefix comment at a given address."""
        return HopperLowLevel.getCommentAtAddress(self.__internal_segment_addr__,addr)
    def setCommentAtAddress(self,addr,comment):
        """Set the prefix comment at a given address."""
        return HopperLowLevel.setCommentAtAddress(self.__internal_segment_addr__,addr,comment)
    def getInlineCommentAtAddress(self,addr):
        """Get the inline comment at a given address."""
        return HopperLowLevel.getInlineCommentAtAddress(self.__internal_segment_addr__,addr)
    def setInlineCommentAtAddress(self,addr,comment):
        """Set the inline comment at a given address."""
        return HopperLowLevel.setInlineCommentAtAddress(self.__internal_segment_addr__,addr,comment)
    def getInstructionAtAddress(self,addr):
        """Get the disassembled instruction at a given address."""
        infos = HopperLowLevel.getInstructionAtAddress(self.__internal_segment_addr__,addr)
        if infos == None:
            return None
        return Instruction(infos[0], infos[1], infos[2], infos[3], infos[4], infos[5], infos[6])
    def getReferencesOfAddress(self,addr):
        """Get the list of addresses that reference a given address."""
        return HopperLowLevel.getReferencesOfAddress(self.__internal_segment_addr__,addr)
    def getReferencesFromAddress(self,addr):
        """Get the list of addresses referenced by a given address."""
        return HopperLowLevel.getReferencesFromAddress(self.__internal_segment_addr__,addr)
    def addReference(self,addr,referenced):
        """Add a cross reference to the 'referenced' address from 'addr' address."""
        return HopperLowLevel.addReference(self.__internal_segment_addr__,addr,referenced)
    def removeReference(self,addr,referenced):
        """Remove the cross reference to the 'referenced' address from 'addr' address."""
        return HopperLowLevel.removeReference(self.__internal_segment_addr__,addr,referenced)
    def getLabelCount(self):
        """Get the number of named addresses."""
        return HopperLowLevel.getLabelCount(self.__internal_segment_addr__)
    def getLabelName(self,index):
        """Get a label name by index."""
        return HopperLowLevel.getLabelName(self.__internal_segment_addr__,index)
    def labelIterator(self):
        """Iterate over all the labels of a segment."""
        for label in self.getLabelsList():
            yield label
    def getLabelsList(self):
        """Returns a list with all the label of a segment."""
        return HopperLowLevel.getLabelsList(self.__internal_segment_addr__)
    def getNamedAddresses(self):
        """Returns a list of all addresses with a label name. The list has the same order as the list returned by getLabelsList."""
        return HopperLowLevel.getNamedAddresses(self.__internal_segment_addr__)
    def getProcedureCount(self):
        """Returns the number of procedures that has been defined in this segment."""
        return HopperLowLevel.getProcedureCount(self.__internal_segment_addr__)
    def getProcedureAtIndex(self,index):
        """Returns the Nth Procedure object of the segment."""
        return Procedure(self.__internal_segment_addr__,index)
    def getProcedureIndexAtAddress(self,address):
        """Returns the index of the procedure at a given address of the segment, or -1 if there is no procedure defined there."""
        return HopperLowLevel.getProcedureIndexAtAddress(self.__internal_segment_addr__,address)
    def getProcedureAtAddress(self,address):
        """Returns the Procedure object at a given address of the segment, or None if there is no procedure defined at there."""
        index=self.getProcedureIndexAtAddress(address)
        if index == -1:
            return None
        else:
            return self.getProcedureAtIndex(index)
    def getInstructionStart(self,address):
        """Returns the lowest address value of the instruction found at a particular address. If the given address"""
        """is in the middle of an instruction, Hopper will look back to find the first byte of this instruction."""
        return HopperLowLevel.nearestBlock(self.__internal_segment_addr__,address)
    def getObjectLength(self,address):
        """Returns the length in bytes of the object at this address. The object can be an instruction, a data, etc."""
        return HopperLowLevel.objectLength(self.__internal_segment_addr__,address)
    def isPartOfAnArray(self,address):
        """Returns True if the address is part of an array."""
        return HopperLowLevel.partOfAnArray(self.__internal_segment_addr__,address)
    def getArrayStartAddress(self,address):
        """Returns the array start address, or BAD_ADDRESS if not inside an array."""
        return HopperLowLevel.arrayStartAddress(self.__internal_segment_addr__,address)
    def getArrayElementCount(self,address):
        """Returns the number of element in the array, or 0 if not inside an array."""
        return HopperLowLevel.arrayElementCount(self.__internal_segment_addr__,address)
    def getArrayElementAddress(self,address,index):
        """Returns the address of the element at the given index, or BAD_ADDRESS if not inside an array."""
        return HopperLowLevel.arrayElementAddress(self.__internal_segment_addr__,address,index)
    def getArrayElementSize(self,address):
        """Returns the size in bytes of a single element of the array, or 0 if not inside an array."""
        return HopperLowLevel.arrayElementSize(self.__internal_segment_addr__,address)

class Document:
    """This class represents the disassembled document. A document is a set of segments."""
    
    FORMAT_DEFAULT = 0
    FORMAT_HEXADECIMAL = 1
    FORMAT_DECIMAL = 2
    FORMAT_OCTAL = 3
    FORMAT_CHARACTER = 4
    FORMAT_STACKVARIABLE = 5
    FORMAT_OFFSET = 6
    FORMAT_ADDRESS = 7
    FORMAT_FLOAT = 8
    FORMAT_BINARY = 9

    FORMAT_STRUCTURED = 10
    FORMAT_ENUM = 11
    FORMAT_ADDRESS_DIFF=12

    FORMAT_NEGATE = 0x20
    FORMAT_LEADINGZEROES = 0x40
    FORMAT_SIGNED = 0x80
    
    def __init__(self,addr):
        self.__internal_document_addr__ = addr
    def __eq__(self,other):
        return other.__class__ == self.__class__ and self.__internal_document_addr__ == other.__internal_document_addr__
    def __ne__(self,other):
        return other.__class__ != self.__class__ or self.__internal_document_addr__ != other.__internal_document_addr__
    @staticmethod
    def newDocument():
        """Creates and returns a new empty document."""
        return Document(HopperLowLevel.newDocument())
    @staticmethod
    def getCurrentDocument():
        """Returns the current document."""
        return Document(HopperLowLevel.currentDocument())
    @staticmethod
    def getAllDocuments():
        """Returns a list of all currently opened documents."""
        return [Document(d) for d in HopperLowLevel.allDocuments()]
    @staticmethod
    def ask(msg):
        """Open a window containing a text field, and wait for the user to give a string value. Returns the string, or returns None if the Cancel button is hit."""
        return HopperLowLevel.ask(msg)
    @staticmethod
    def askFile(msg,path,save):
        """Open a file dialog with a specified title, in order to select a file. The 'save' parameter allows you to choose between on 'open' or a 'save' dialog."""
        return HopperLowLevel.askFile(msg, path if path != None else "", 1 if save else 0)
    @staticmethod
    def askDirectory(msg,path):
        """Open a file dialog with a specified title, in order to select a directory."""
        return HopperLowLevel.askDirectory(msg, path if path != None else "")
    @staticmethod
    def message(msg,buttons):
        """Open a window containing a text field and a set of buttons. The 'Buttons' parameter is a list of strings. The function returns the index of the clicked button."""
        return HopperLowLevel.message(msg,buttons)
    def closeDocument(self):
        """Close the document."""
        HopperLowLevel.closeDocument(self.__internal_document_addr__)
    def loadDocumentAt(self,path):
        """Load a document at a given path."""
        HopperLowLevel.loadDocumentAt(self.__internal_document_addr__,path)
    def saveDocument(self):
        """Save the document."""
        HopperLowLevel.saveDocument(self.__internal_document_addr__)
    def saveDocumentAt(self,path):
        """Save the document at a given path."""
        HopperLowLevel.saveDocumentAt(self.__internal_document_addr__,path)
    def getDocumentName(self):
        """Returns the document display name."""
        return HopperLowLevel.documentName(self.__internal_document_addr__)
    def setDocumentName(self,name):
        """Set the document display name."""
        HopperLowLevel.setDocumentName(self.__internal_document_addr__,name)
    def backgroundProcessActive(self):
        """Returns True if the background analysis is still running."""
        return HopperLowLevel.backgroundProcessActive(self.__internal_document_addr__)
    def requestBackgroundProcessStop(self):
        """Request the background analysis to stop as soon as possible, and wait for its termination."""
        HopperLowLevel.requestBackgroundProcessStop(self.__internal_document_addr__)
    def waitForBackgroundProcessToEnd(self):
        """Wait until the background analysis is ended."""
        HopperLowLevel.waitForBackgroundProcessToEnd(self.__internal_document_addr__)
    def assemble(self,instr,address,syntax):
        """Assemble an instruction, and returns the bytes as an array. The instruction is NOT injected in the document: the address given to the function is used to encode the instruction. You wan use the writeByte method to inject an assembled instruction."""
        """The first argument is the instruction to be assembled. The second is the address of the instruction. The last parameter is the syntax variant index. For the Intel processor, syntax = 0 for Intel syntax, and 1 for AT&amp;T syntax."""
        return HopperLowLevel.assemble(self.__internal_document_addr__,instr,address,syntax)
    def getDatabaseFilePath(self):
        """Returns the path of the current Hopper database for this document (the HOP file)."""
        return HopperLowLevel.getDatabaseFilePath(self.__internal_document_addr__)
    def getExecutableFilePath(self):
        """Returns the path of the executable being analyzed."""
        return HopperLowLevel.getExecutableFilePath(self.__internal_document_addr__)
    def setExecutableFilePath(self,path):
        """Set the path of the executable being analyzed."""
        return HopperLowLevel.setExecutableFilePath(self.__internal_document_addr__,path)
    def log(self,msg):
        """Display a string message into the log window of the document."""
        HopperLowLevel.log(self.__internal_document_addr__,msg)
    def newSegment(self,start_address,length):
        """Create a new segment of 'length' bytes starting at 'start_address'."""
        HopperLowLevel.newSegment(self.__internal_document_addr__,start_address,length)
        return self.getSegmentAtAddress(start_address)
    def deleteSegment(self,seg_index):
        """Delete the segment at a given index. Return True if succeeded."""
        return HopperLowLevel.deleteSegment(self.__internal_document_addr__,seg_index)
    def renameSegment(self,seg_index,name):
        """Rename the segment at a given index. Return True if succeeded."""
        return HopperLowLevel.renameSegment(self.__internal_document_addr__,seg_index,name)
    def getSegmentCount(self):
        """Returns the number of segment the document contains."""
        return HopperLowLevel.getSegmentCount(self.__internal_document_addr__);
    def getSegment(self,index):
        """Returns a segment by index. The returned object is an instance of the Segment class. If the index of not in the range [0;count[, the function returns None."""
        addr = HopperLowLevel.getSegmentAddress(self.__internal_document_addr__,index)
        if addr == 0:
            return None
        return Segment(addr)
    def getSegmentByName(self,name):
        """Returns a segment by name. Return None if no segment with this name was found. If multiple segments have this name, the first one is returned."""
        addr = HopperLowLevel.getSegmentAddressByName(self.__internal_document_addr__,name)
        if addr == 0:
            return None
        return Segment(addr)
    def getSectionByName(self,name):
        """Returns a section by name. Return None if no segment with this name was found. If multiple sections have this name, the first one is returned."""
        addr = HopperLowLevel.getSectionAddressByName(self.__internal_document_addr__,name)
        if addr == 0:
            return None
        return Section(addr)
    def getSegmentsList(self):
        """Returns a list containing all the segments."""
        return [self.getSegment(x) for x in xrange(self.getSegmentCount())]
    def getSegmentIndexAtAddress(self,addr):
        """Returns the segment index for a particular address."""
        return HopperLowLevel.getSegmentIndexAtAddress(self.__internal_document_addr__,addr)
    def getSegmentAtAddress(self,addr):
        """Returns the segment for a particular address."""
        idx=self.getSegmentIndexAtAddress(addr)
        if idx == -1:
            return None
        return self.getSegment(idx)
    def getSectionAtAddress(self,addr):
        """Returns the section for a particular address."""
        seg=self.getSegmentAtAddress(addr)
        if seg == None:
            return None
        return seg.getSectionAtAddress(addr)
    def getCurrentSegmentIndex(self):
        """Returns the segment index where the cursor is. Returns -1 if the current segment cannot be located."""
        return HopperLowLevel.getCurrentSegmentIndex(self.__internal_document_addr__)
    def getCurrentSegment(self):
        """Returns the segment where the cursor is. Returns None if the current segment cannot be located."""
        index = HopperLowLevel.getCurrentSegmentIndex(self.__internal_document_addr__)
        if index == -1:
            return None
        else:
            return self.getSegment(index)
    def getCurrentSection(self):
        """Returns the section where the cursor is. Returns None if the current section cannot be located."""
        return self.getSectionAtAddress(self.getCurrentAddress())
    def getCurrentProcedure(self):
        """Returns the Procedure object where the cursor is. Returns None if there is no procedure there."""
        seg = self.getCurrentSegment()
        if seg == None:
            return None
        return seg.getProcedureAtAddress(self.getCurrentAddress())
    def getCurrentAddress(self):
        """Returns the address where the cursor currently is."""
        return HopperLowLevel.getCurrentAddress(self.__internal_document_addr__)
    def setCurrentAddress(self,addr):
        """Set the address where the cursor currently is."""
        return HopperLowLevel.setCurrentAddress(self.__internal_document_addr__,addr)
    def getSelectionAddressRange(self):
        """Returns a list, containing two addresses. Those address represents the range of bytes covered by the selection."""
        return HopperLowLevel.getSelectionAddressRange(self.__internal_document_addr__)
    def moveCursorAtAddress(self,addr):
        """Move the cursor at a given address."""
        HopperLowLevel.moveCursorAtAddress(self.__internal_document_addr__,addr)
    def selectAddressRange(self,addrRange):
        """Select a range of byte. The awaited argument is a list containing exactly two address."""
        HopperLowLevel.selectAddressRange(self.__internal_document_addr__,addrRange[0],addrRange[1])
    def getFileOffsetFromAddress(self,addr):
        """Returns the file offset corresponding to the given address."""
        return HopperLowLevel.getFileOffsetFromAddress(self.__internal_document_addr__, addr)
    def getAddressFromFileOffset(self,offset):
        """Returns the address corresponding to the given file offset."""
        return HopperLowLevel.getAddressFromFileOffset(self.__internal_document_addr__, offset)
    def is64Bits(self):
        """Returns True if the disassembled document is interpreted as a 64 bits binary."""
        return HopperLowLevel.is64Bits(self.__internal_document_addr__);
    def getEntryPoint(self):
        """Returns the entry point of the document."""
        return HopperLowLevel.getEntryPoint(self.__internal_document_addr__)
    def moveCursorAtEntryPoint(self):
        """Move the cursor at the entry point."""
        self.moveCursorAtAddress(self.getEntryPoint())
    def getHighlightedWord(self):
        """Returns the word that is currently highlighted in the assembly view."""
        return HopperLowLevel.getHighlightedWord(self.__internal_document_addr__)
    def setNameAtAddress(self,addr,name):
        """Set the label name at a given address."""
        seg=self.getSegmentAtAddress(addr)
        if seg != None:
            return seg.setNameAtAddress(addr,name)
        return False
    def getNameAtAddress(self,addr):
        """Get the label name at a given address."""
        seg=self.getSegmentAtAddress(addr)
        if seg != None:
            return seg.getNameAtAddress(addr)
        return None
    def getAddressForName(self,name):
        """Get the address associated to a given name."""
        return HopperLowLevel.getAddressForName(self.__internal_document_addr__,name)
    def refreshView(self):
        """Force the assembly view to be refresh."""
        HopperLowLevel.refreshView(self.__internal_document_addr__)
    def moveCursorOneLineDown(self):
        """Move the current line down, and remove the multiselection if needed. Returns True if cursor moved."""
        return HopperLowLevel.moveCursorOneLineDown(self.__internal_document_addr__)
    def moveCursorOneLineUp(self):
        """Move the current line up, and remove the multiselection if needed. Returns True if cursor moved."""
        return HopperLowLevel.moveCursorOneLineUp(self.__internal_document_addr__)
    def getRawSelectedLines(self):
        """Returns a list of strings corresponding to the current selection."""
        return HopperLowLevel.getRawSelectedLines(self.__internal_document_addr__)
    def addTagAtAddress(self,tag,addr):
        """Add a tag at a particular address."""
        HopperLowLevel.addTagAtAddress(self.__internal_document_addr__,tag.__tag_internal__,addr)
    def removeTagAtAddress(self,tag,addr):
        """Remove the tag at a particular address."""
        HopperLowLevel.removeTagAtAddress(self.__internal_document_addr__,tag.__tag_internal__,addr)
    def hasTagAtAddress(self,tag,addr):
        """Returns True if the tag is present at this address."""
        return HopperLowLevel.hasTagAtAddress(self.__internal_document_addr__,tag.__tag_internal__,addr)
    def getTagCountAtAddress(self,addr):
        """Returns the number of tags at a given address."""
        return HopperLowLevel.getTagCountAtAddress(self.__internal_document_addr__,addr)
    def getTagAtAddressByIndex(self,addr,index):
        """Returns the Nth tag present at a given address."""
        tag_ptr = HopperLowLevel.getTagAtAddressByIndex(self.__internal_document_addr__,addr,index)
        return Tag(tag_ptr) if tag_ptr != 0 else None
    def tagIteratorAtAddress(self,addr):
        """Iterates over all tags present at a given address."""
        for index in xrange(self.getTagCountAtAddress(addr)):
            yield self.getTagAtAddressByIndex(addr,index)
    def getTagListAtAddress(self,addr):
        """Returns the list of all tags present at a given address"""
        return [tag for tag in self.tagIteratorAtAddress(addr)]
    def getTagCount(self):
        """Returns the total number of tags available."""
        return HopperLowLevel.getTagCount(self.__internal_document_addr__)
    def getTagAtIndex(self,index):
        """Returns a Tag object, or None if the index does not exists."""
        tag_ptr = HopperLowLevel.getTagPtrAtIndex(self.__internal_document_addr__,index)
        return Tag(tag_ptr) if tag_ptr != 0 else None
    def tagIterator(self):
        """Iterate over all the tags."""
        for index in xrange(self.getTagCount()):
            yield self.getTagAtIndex(index)
    def getTagList(self):
        """Returns a list of all tags."""
        return [tag for tag in self.tagIterator()]
    def buildTag(self,name):
        """Build a tag with a given name. If a tag with the same name already exists, it return the existing tag."""
        tag_ptr = HopperLowLevel.buildTagPtrWithName(self.__internal_document_addr__,name)
        return Tag(tag_ptr)
    def getTagWithName(self,name):
        """Returns a Tag object if a tag with this name already exists, or None."""
        tag_ptr = HopperLowLevel.getTagPtrWithName(self.__internal_document_addr__,name)
        return Tag(tag_ptr) if tag_ptr != 0 else None
    def destroyTag(self,tag):
        """Remove the tag from every location, and delete it."""
        HopperLowLevel.destroyTag(self.__internal_document_addr__,tag.__tag_internal__)
    def hasColorAtAddress(self,addr):
        """Returns True if a color has been defined at the given address."""
        return HopperLowLevel.hasColorAtAddress(self.__internal_document_addr__,addr)
    def setColorAtAddress(self,color,addr):
        """Sets the color at a given address. The color is a 32bits integer representing the hexadecimal color in the form #AARRGGBB."""
        return HopperLowLevel.setColorAtAddress(self.__internal_document_addr__,color,addr)
    def getColorAtAddress(self,addr):
        """Returns the color at a given address. The color is a 32bits integer representing the hexadecimal color in the form #AARRGGBB."""
        return HopperLowLevel.colorAtAddress(self.__internal_document_addr__,addr)
    def removeColorAtAddress(self,addr):
        """Remove the color at a given address."""
        HopperLowLevel.removeColorAtAddress(self.__internal_document_addr__,addr)
    def readBytes(self,addr,length):
        """Read bytes from a mapped segment, and return a string. Returns False if no segments was found for this range."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readBytes(addr,length)
    def readByte(self,addr):
        """Read a byte from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readByte(addr)
    def readUInt16LE(self,addr):
        """Read a 16 bits little endian integer from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readUInt16LE(addr)
    def readUInt32LE(self,addr):
        """Read a 32 bits little endian integer from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readUInt32LE(addr)
    def readUInt64LE(self,addr):
        """Read a 64 bits little endian integer from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readUInt64LE(addr)
    def readUInt16BE(self,addr):
        """Read a 16 bits big endian integer from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readUInt16BE(addr)
    def readUInt32BE(self,addr):
        """Read a 32 bits big endian integer from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readUInt32BE(addr)
    def readUInt64BE(self,addr):
        """Read a 64 bits bif endian integer from a mapped segment. Returns False if no segments was found for this address."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.readUInt64BE(addr)
    def writeBytes(self,addr,byteStr):
        """Write bytes to a mapped segment. Bytes are given as a string. Returns False if no segments was found for this range."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeBytes(addr,byteStr)
    def writeByte(self,addr,value):
        """Write a byte to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeByte(addr,value)
    def writeUInt16LE(self,addr,value):
        """Write a 16 bits little endian integer to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeUInt16LE(addr,value)
    def writeUInt32LE(self,addr,value):
        """Write a 32 bits little endian integer to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeUInt32LE(addr,value)
    def writeUInt64LE(self,addr,value):
        """Write a 64 bits little endian integer to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeUInt64LE(addr,value)
    def writeUInt16BE(self,addr,value):
        """Write a 16 bits big endian integer to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeUInt16BE(addr,value)
    def writeUInt32BE(self,addr,value):
        """Write a 32 bits big endian integer to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeUInt32BE(addr,value)
    def writeUInt64BE(self,addr,value):
        """Write a 64 bits big endian integer to a mapped segment. Returns True if succeeded."""
        segment = self.getSegmentAtAddress(addr)
        if segment == None: return False
        return segment.writeUInt64BE(addr,value)
    def getOperandFormat(self,addr,index):
        """Returns the format requested by the user for a given intruction operand."""
        return HopperLowLevel.getOperandFormat(self.__internal_document_addr__,addr,index)
    def getOperandFormatRelativeTo(self,addr,index):
        """Returns the address to which the format is relative. Usually used for FORMAT_ADDRESS_DIFF format."""
        return HopperLowLevel.getOperandFormatRelativeTo(self.__internal_document_addr__,addr,index)
    def setOperandFormat(self,addr,index,fmt):
        """Set the format of a given intruction operand."""
        return HopperLowLevel.setOperandFormat(self.__internal_document_addr__,addr,index,fmt)
    def setOperandRelativeFormat(self,addr,relto,index,fmt):
        """Set the relative format of a given intruction operand. This version allows one to provide an address"""
        """used for the relative formats, like FORMAT_ADDRESS_DIFF."""
        return HopperLowLevel.setOperandRelativeFormat(self.__internal_document_addr__,addr,relto,index,fmt)
    def getInstructionStart(self,address):
        """Returns the lowest address value of the instruction found at a particular address. If the given address"""
        """is in the middle of an instruction, Hopper will look back to find the first byte of this instruction."""
        segment = self.getSegmentAtAddress(address)
        if segment == None: return BAD_ADDRESS
        return segment.getInstructionStart(address)
    def getObjectLength(self,address):
        """Returns the length in bytes of the object at this address. The object can be an instruction, a data, etc."""
        segment = self.getSegmentAtAddress(address)
        if segment == None: return BAD_ADDRESS
        return segment.getObjectLength(address)
    def generateObjectiveCHeader(self):
        """Returns a bytearray object containing the generated Objective-C header extracted from the file's metadata."""
        return HopperLowLevel.generateObjectiveCHeader(self.__internal_document_addr__)
    def produceNewExecutable(self,remove_sig=False):
        """Produce a new executable including all the modifications."""
        """The optional argument is a boolean indicating if the signature is to be removed in the case of a Mach-O file."""
        """Returns a string containing the produced executable."""
        return HopperLowLevel.produceNewExecutable(self.__internal_document_addr__,1 if remove_sig else 0)

class GlobalInformation:
    """An object containing various information about the current version of Hopper."""
    @staticmethod
    def getHopperMajorVersion():
        """Returns the major version number. If Hopper is at version 4.1.2, it'll return "4"."""
        return HopperLowLevel.getMajorVersion()
    @staticmethod
    def getHopperMinorVersion():
        """Returns the minor version number. If Hopper is at version 4.1.2, it'll return "1"."""
        return HopperLowLevel.getMinorVersion()
    @staticmethod
    def getHopperRevisionNumber():
        """Returns the revision version number. If Hopper is at version 4.1.2, it'll return "2"."""
        return HopperLowLevel.getRevision()
    @staticmethod
    def getHopperVersion():
        """Returns a string with the complete Hopper's version number (ie, something like "4.1.2")"""
        return "%d.%d.%d" % (GlobalInformation.getHopperMajorVersion(), GlobalInformation.getHopperMinorVersion(), GlobalInformation.getHopperRevisionNumber())

import sys
sys.stdout = HopperStdRedirection(0)
sys.stderr = HopperStdRedirection(1)
