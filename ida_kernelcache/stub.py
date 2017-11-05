#
# ida_kernelcache/stub.py
# Brandon Azad
#
# Functions for analyzing stub functions in the kernelcache.
#

import re

import idc
import idautils
import idaapi

import ida_utilities as idau
import internal

_log = idau.make_log(1, __name__)

kernelcache_stub_suffix = '___stub_'
"""The suffix that gets appended to a symbol to create the stub name, without the stub ID."""

_stub_regex = re.compile(r"^(\S+)" + kernelcache_stub_suffix + r"\d+$")
"""A regular expression to match and extract the target name from a stub symbol."""

def stub_name_target(stub_name):
    """Get the target to which a stub name refers.

    No checks are performed to ensure that the target actually exists.
    """
    match = _stub_regex.match(stub_name)
    if not match:
        return None
    return match.group(1)

def symbol_references_stub(symbol_name):
    """Check if the symbol name references a stub."""
    return kernelcache_stub_suffix in symbol_name

def _process_stub_template_1(stub):
    """A template to match the following stub pattern:

    ADRP X<reg>, #<offset>@PAGE
    LDR  X<reg>, [X<reg>, #<offset>@PAGEOFF]
    BR   X<reg>
    """
    adrp, ldr, br = idau.Instructions(stub, count=3)
    if (adrp.itype == idaapi.ARM_adrp and adrp.Op1.type == idaapi.o_reg
            and adrp.Op2.type == idaapi.o_imm
            and ldr.itype == idaapi.ARM_ldr and ldr.Op1.type == idaapi.o_reg
            and ldr.Op2.type == idaapi.o_displ and ldr.auxpref == 0
            and br.itype == idaapi.ARM_br and br.Op1.type == idaapi.o_reg
            and adrp.Op1.reg == ldr.Op1.reg == ldr.Op2.reg == br.Op1.reg):
        offset = adrp.Op2.value + ldr.Op2.addr
        target = idau.read_word(offset)
        if target and idau.is_mapped(target):
            return target

_stub_processors = (
    _process_stub_template_1,
)

def stub_target(stub_func):
    """Find the target function called by a stub.

    Arm64 only."""
    # Each processing function in _stub_processors takes the address of a stub function and returns
    # the address of the target function.
    for process in _stub_processors:
        try:
            target = process(stub_func)
            if target:
                return target
        except:
            pass

def _symbolicate_stub(stub, target, next_stub):
    """Set a symbol for a stub function."""
    name = idau.get_ea_name(target, user=True)
    if not name:
        _log(3, 'Stub {:#x} has target {:#x} without a name', stub, target)
        return False
    # Sometimes the target of the stub is a thunk in another kext. This is sometimes OK, but makes
    # a right mess of things when that thunk is itself a jump function for another stub, and
    # especially when there are multiple such jump functions to that stub in that kext.
    # Autorenaming of thunks interacts poorly with autonaming of stubs (you get things like
    # 'j_TARGET___stub_2_0', which stub_name_target() no longer thinks of as a stub). Thus, if the
    # current thing has '__stub_' in it, don't rename. The reason we don't just extract the inner
    # stub reference is that these jump functions are really wrappers with different names and
    # semantics in the original code, so it's not appropriate for us to cover that up with a stub.
    if symbol_references_stub(name):
        _log(2, 'Stub {:#x} has target {:#x} (name {}) that references another stub', stub, target,
                name)
        return False
    symbol = next_stub(name)
    if symbol is None:
        _log(0, 'Could not generate stub symbol for {}: names exhausted', name)
        return False
    if not idau.set_ea_name(stub, symbol, auto=True):
        _log(2, 'Could not set name {} for stub at {:#x}', symbol, stub)
        return False
    return True

def _process_possible_stub(stub, make_thunk, next_stub):
    """Try to process a stub function."""
    # First, make sure this is a stub format we recognize.
    target = stub_target(stub)
    if not target:
        _log(0, 'Unrecognized stub format at {:#x}', stub)
        return False
    # Next, check if IDA sees this as a function chunk rather than a function, and correct it if
    # reasonable.
    if not idau.force_function(stub):
        _log(1, 'Could not convert stub to function at {:#x}', stub)
        return False
    # Next, set the appropriate flags on the stub. Make the stub a thunk if that was requested.
    flags = idc.GetFunctionFlags(stub)
    if flags == -1:
        _log(1, 'Could not get function flags for stub at {:#x}', stub)
        return False
    target_flags = idc.GetFunctionFlags(target)
    if target_flags != -1 and target_flags & idc.FUNC_NORET:
        flags |= idc.FUNC_NORET
    if make_thunk:
        flags |= idc.FUNC_THUNK
    if idc.SetFunctionFlags(stub, flags | idc.FUNC_THUNK) == 0:
        _log(1, 'Could not set function flags for stub at {:#x}', stub)
        return False
    # Next, ensure that IDA sees the target as a function, but continue anyway if that fails.
    if not idau.force_function(target):
        _log(1, 'Stub {:#x} has target {:#x} that is not a function', stub, target)
    # Finally symbolicate the stub.
    if not _symbolicate_stub(stub, target, next_stub):
        return False
    return True

def _process_stubs_section(segstart, make_thunk, next_stub):
    """Process all the functions in a __stubs section."""
    segend = idc.SegEnd(segstart)
    # We'll go through each address and check if it has a reference. If it does, it is likely a
    # stub. As long as the address doesn't already have a stub name, process it.
    for ea in idau.Addresses(segstart, segend, step=1):
        if idc.isRef(idc.GetFlags(ea)) and not stub_name_target(idau.get_ea_name(ea)):
            _process_possible_stub(ea, make_thunk, next_stub)

def initialize_stub_symbols(make_thunk=True):
    """Populate IDA with information about the stubs in an iOS kernelcache.

    Search through the kernelcache for stubs (__stubs sections) and rename each stub function
    according to the target function it calls.

    Arm64 only.

    Options:
        make_thunk: Set the thunk attribute for each stub function. Default is True.
    """
    next_stub = internal.make_name_generator(kernelcache_stub_suffix)
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('__stubs'):
            continue
        _log(3, 'Processing segment {}', segname)
        _process_stubs_section(ea, make_thunk, next_stub)

