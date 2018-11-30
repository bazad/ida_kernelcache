#
# ida_kernelcache/offset.py
# Brandon Azad
#
# Functions for converting and symbolicating offsets.
#

import re

import idc
import idautils

import ida_utilities as idau
import internal
import kernel
import stub

_log = idau.make_log(1, __name__)

def initialize_data_offsets():
    """Convert offsets in data segments into offsets in IDA.

    Segment names must be initialized with segments.initialize_segments() first.
    """
    # Normally, for user-space programs, this operation would be dangerous because there's a good
    # chance that a valid userspace address would happen to show up in regular program data that is
    # not actually an address. However, since kernel addresses are numerically much larger, the
    # chance of this happening is much less.
    for seg in idautils.Segments():
        name = idc.SegName(seg)
        if not (name.endswith('__DATA_CONST.__const') or name.endswith('__got')
                or name.endswith('__DATA.__data')):
            continue
        for word, ea in idau.ReadWords(seg, idc.SegEnd(seg), addresses=True):
            if idau.is_mapped(word, value=False):
                idc.OpOff(ea, 0, 0)

kernelcache_offset_suffix = '___offset_'
"""The suffix that gets appended to a symbol to create the offset name, without the offset ID."""

_offset_regex = re.compile(r"^(\S+)" + kernelcache_offset_suffix + r"\d+$")
"""A regular expression to match and extract the target name from an offset symbol."""

def offset_name_target(offset_name):
    """Get the target to which an offset name refers.

    No checks are performed to ensure that the target actually exists.
    """
    match = _offset_regex.match(offset_name)
    if not match:
        return None
    return match.group(1)

def _process_offset(offset, ea, next_offset):
    """Process an offset in a __got section."""
    # Convert the address containing the offset into an offset in IDA, but continue if it fails.
    if not idc.OpOff(ea, 0, 0):
        _log(1, 'Could not convert {:#x} into an offset', ea)
    # Get the name to which the offset refers.
    name = idau.get_ea_name(offset, user=True)
    if not name:
        _log(3, 'Offset at address {:#x} has target {:#x} without a name', ea, offset)
        return False
    # Make sure this isn't an offset to another stub or to a jump function to another stub. See the
    # comment in _symbolicate_stub.
    if stub.symbol_references_stub(name):
        _log(1, 'Offset at address {:#x} has target {:#x} (name {}) that references a stub', ea,
                offset, name)
        return False
    # Set the new name for the offset.
    symbol = next_offset(name)
    if symbol is None:
        _log(0, 'Could not generate offset symbol for {}: names exhausted', name)
        return False
    if not idau.set_ea_name(ea, symbol, auto=True):
        _log(2, 'Could not set name {} for offset at {:#x}', symbol, ea)
        return False
    return True

def _process_offsets_section(segstart, next_offset):
    """Process all the offsets in a __got section."""
    for offset, ea in idau.ReadWords(segstart, idc.SegEnd(segstart), addresses=True):
        if not offset_name_target(idau.get_ea_name(ea)):
            # This is not a previously named offset.
            if idau.is_mapped(offset, value=False):
                _process_offset(offset, ea, next_offset)
            else:
                _log(-1, 'Offset {:#x} at address {:#x} is unmapped', offset, ea)

def initialize_offset_symbols():
    """Populate IDA with information about the offsets in an iOS kernelcache.

    Search through the kernelcache for global offset tables (__got sections), convert each offset
    into an offset type in IDA, and rename each offset according to its target.

    This function does nothing in the newer 12-merged format kernelcache.
    """
    next_offset = internal.make_name_generator(kernelcache_offset_suffix)
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('__got'):
            continue
        _log(2, 'Processing segment {}', segname)
        _process_offsets_section(ea, next_offset)

