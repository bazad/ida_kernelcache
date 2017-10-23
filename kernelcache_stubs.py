#
# kernelcache_stubs.py
# Brandon Azad
#
# Process offsets and stub functions in a kernelcache.
#

from ida_utilities import *

from collections import defaultdict
import re

_log_level = 1

def _log(level, fmt, *args):
    if level <= _log_level:
        print 'kernelcache_stubs: ' + fmt.format(*args)

kernelcache_offset_suffix = '___offset_'
"""The suffix that gets appended to a symbol to create the offset name, without the offset ID."""

kernelcache_stub_suffix = '___stub_'
"""The suffix that gets appended to a symbol to create the stub name, without the stub ID."""

_offset_regex = re.compile(r"^(\S+)" + kernelcache_offset_suffix + r"\d+$")
"""A regular expression to match and extract the target name from an offset symbol."""

_stub_regex = re.compile(r"^(\S+)" + kernelcache_stub_suffix + r"\d+$")
"""A regular expression to match and extract the target name from a stub symbol."""

def kernelcache_offset_name_target(offset_name):
    """Get the target to which an offset name refers.

    No checks are performed to ensure that the target actually exists.
    """
    match = _offset_regex.match(offset_name)
    if not match:
        return None
    return match.group(1)

def kernelcache_stub_name_target(stub_name):
    """Get the target to which a stub name refers.

    No checks are performed to ensure that the target actually exists.
    """
    match = _stub_regex.match(stub_name)
    if not match:
        return None
    return match.group(1)

def kernelcache_symbol_references_stub(symbol_name):
    """Check if the symbol name references a stub."""
    return kernelcache_stub_suffix in symbol_name

def _process_offset(offset, ea, next_offset):
    """Process an offset in a __got section."""
    # Convert the address containing the offset into an offset in IDA, but continue if it fails.
    if not idc.OpOff(ea, 0, 0):
        _log(1, 'Could not convert {:#x} into an offset', ea)
    # Get the name to which the offset refers.
    name = get_ea_name(offset, username=True)
    if not name:
        _log(3, 'Offset at address {:#x} has target {:#x} without a name', ea, offset)
        return False
    # Make sure this isn't an offset to another stub or to a jump function to another stub. See the
    # comment in _symbolicate_stub.
    if kernelcache_symbol_references_stub(name):
        _log(1, 'Offset at address {:#x} has target {:#x} (name {}) that references a stub', ea,
                offset, name)
        return False
    # Set the new name for the offset.
    symbol = next_offset(name)
    if symbol is None:
        _log(0, 'Could not generate offset symbol for {}: names exhausted', name)
        return False
    if not set_ea_name(ea, symbol, auto=True):
        _log(2, 'Could not set name {} for offset at {:#x}', symbol, ea)
        return False
    return True

def _process_offsets_section(segstart, next_offset):
    """Process all the offsets in a __got section."""
    for offset, ea in ReadWords(segstart, idc.SegEnd(segstart), addresses=True):
        if not kernelcache_offset_name_target(get_ea_name(ea)):
            # This is not a previously named offset.
            if is_mapped(offset, value=False):
                _process_offset(offset, ea, next_offset)
            else:
                _log(-1, 'Offset {:#x} at address {:#x} is unmapped', offset, ea)

def kernelcache_symbolicate_offsets():
    """Populate IDA with information about the offsets in an iOS kernelcache.

    Search through the kernelcache for global offset tables (__got sections), convert each offset
    into an offset type in IDA, and rename each offset according to its target.
    """
    next_offset = _make_generator(kernelcache_offset_suffix)
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('.__got'):
            continue
        _log(2, 'Processing segment {}', segname)
        _process_offsets_section(ea, next_offset)

def _process_stub_template_1(stub):
    """A template to match the following stub pattern:

    ADRP X<reg>, #<offset>@PAGE
    LDR  X<reg>, [X<reg>, #<offset>@PAGEOFF]
    BR   X<reg>
    """
    adrp, ldr, br = Instructions(stub, count=3)
    if (adrp.itype == idaapi.ARM_adrp and adrp.Op1.type == idaapi.o_reg
            and adrp.Op2.type == idaapi.o_imm
            and ldr.itype == idaapi.ARM_ldr and ldr.Op1.type == idaapi.o_reg
            and ldr.Op2.type == idaapi.o_displ and ldr.auxpref == 0
            and br.itype == idaapi.ARM_br and br.Op1.type == idaapi.o_reg
            and adrp.Op1.reg == ldr.Op1.reg == ldr.Op2.reg == br.Op1.reg):
        offset = adrp.Op2.value + ldr.Op2.addr
        target = read_word(offset)
        if target and is_mapped(target):
            return target

_stub_processors = (
    _process_stub_template_1,
)

def kernelcache_stub_target(stub_func):
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

def all_xrefs_are_jumps(ea):
    """Check if all xrefs to a linear address are of type Code_Near_Jump."""
    return all(xref.type == idc.fl_JN for xref in idautils.XrefsTo(ea))

def _convert_chunk_to_function(func):
    """Convert code that IDA has classified as a function chunk into a proper function."""
    idc.RemoveFchunk(func, func)
    return idc.MakeFunction(func) != 0

def _is_function_start(ea):
    """Return True if the address is the start of a function."""
    return idc.GetFunctionAttr(ea, idc.FUNCATTR_START) == ea

def _ensure_stub_is_function(stub):
    """Ensure that the given stub is a function type, converting it if necessary."""
    # If it's already a function, we're good.
    if _is_function_start(stub):
        return True
    # Otherwise, make sure all xrefs are jumps, and then convert.
    if all_xrefs_are_jumps(stub):
        return _convert_chunk_to_function(stub)
    return False

def _ensure_target_is_function(target):
    """Ensure that the given target is a function type, converting it if necessary."""
    # If it's already a function, we're good.
    if _is_function_start(target):
        return True
    return idc.MakeFunction(target) != 0

def _symbolicate_stub(stub, target, next_stub):
    """Set a symbol for a stub function."""
    name = get_ea_name(target, username=True)
    if not name:
        _log(3, 'Stub {:#x} has target {:#x} without a name', stub, target)
        return False
    # Sometimes the target of the stub is a thunk in another kext. This is sometimes OK, but makes
    # a right mess of things when that thunk is itself a jump function for another stub, and
    # especially when there are multiple such jump functions to that stub in that kext.
    # Autorenaming of thunks interacts poorly with autonaming of stubs (you get things like
    # 'j_TARGET___stub_2_0', which kernelcache_stub_name_target() no longer thinks of as a stub).
    # Thus, if the current thing has '__stub_' in it, don't rename. The reason we don't just
    # extract the inner stub reference is that these jump functions are really wrappers with
    # different names and semantics in the original code, so it's not appropriate for us to cover
    # that up with a stub.
    if kernelcache_symbol_references_stub(name):
        _log(1, 'Stub {:#x} has target {:#x} (name {}) that references another stub', stub, target,
                name)
        return False
    symbol = next_stub(name)
    if symbol is None:
        _log(0, 'Could not generate stub symbol for {}: names exhausted', name)
        return False
    if not set_ea_name(stub, symbol, auto=True):
        _log(2, 'Could not set name {} for stub at {:#x}', symbol, stub)
        return False
    return True

def _process_possible_stub(stub, make_thunk, next_stub):
    """Try to process a stub function."""
    # First, make sure this is a stub format we recognize.
    target = kernelcache_stub_target(stub)
    if not target:
        _log(0, 'Unrecognized stub format at {:#x}', stub)
        return False
    # Next, check if IDA sees this as a function chunk rather than a function, and correct it if
    # reasonable.
    if not _ensure_stub_is_function(stub):
        _log(1, 'Could not convert stub to function at {:#x}', stub)
        return False
    # Next, make the stub a thunk if that was requested.
    if make_thunk:
        flags = idc.GetFunctionFlags(stub)
        if flags == -1:
            _log(1, 'Could not get function flags for stub at {:#x}', stub)
            return False
        if idc.SetFunctionFlags(stub, flags | idc.FUNC_THUNK) == 0:
            _log(1, 'Could not set function flags for stub at {:#x}', stub)
            return False
    # Next, ensure that IDA sees the target as a function, but continue anyway if that fails.
    if not _ensure_target_is_function(target):
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
    for ea in Addresses(segstart, segend, step=1):
        if idc.isRef(idc.GetFlags(ea)) and not kernelcache_stub_name_target(get_ea_name(ea)):
            _process_possible_stub(ea, make_thunk, next_stub)

def _make_generator(suffix, max_count=999999):
    """Create a unique name generator using the specified template factory."""
    next_index_dict = defaultdict(lambda: 1)
    def get_next(name):
        assert name, 'Invalid symbol name passed to name generator'
        assert suffix not in name, 'Symbol name passed to name generator already contains suffix'
        template = name + suffix
        for index in xrange(next_index_dict[name], max_count):
            new_name = template + str(index)
            if get_name_ea(new_name) == idc.BADADDR:
                next_index_dict[name] = index
                return new_name
        new_index_dict[name] = max_count
        return None
    return get_next

def kernelcache_symbolicate_stubs(make_thunk=True):
    """Populate IDA with information about the stubs in an iOS kernelcache.

    Search through the kernelcache for stubs (__stubs sections) and rename each stub function
    according to the target function it calls.

    Arm64 only.

    Options:
        make_thunk: Set the thunk attribute for each stub function. Default is True.
    """
    next_stub = _make_generator(kernelcache_stub_suffix)
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('.__stubs'):
            continue
        _log(3, 'Processing segment {}', segname)
        _process_stubs_section(ea, make_thunk, next_stub)

