#
# ida_kernelcache/tagged_pointers.py
# Brandon Azad
#
"""ida_kernelcache.tagged_pointers

This module is responsible for processing the tagged pointers in the new iOS 12 kernelcache and
replacing them with their untagged equivalents. All found pointers are also converted into offsets.

In an alternative implementation, we could just add cross-references in IDA. However, I think this
approach is better because it is closer to what the kernelcache looks like at runtime.
"""

import idc
import idautils

import ida_utilities as idau
import kernel

_log = idau.make_log(1, __name__)

def tagged_pointer_tag(tp):
    return (tp >> 48) & 0xffff

def tagged_pointer_untag(tp):
    return tp | 0xffff000000000000

def is_tagged_pointer_format(value):
    return tagged_pointer_tag(value) != 0xffff and \
            (value & 0x0000ffff00000000) == 0x0000fff000000000

def is_tagged_pointer(value):
    return is_tagged_pointer_format(value) and \
            idau.is_mapped(tagged_pointer_untag(value), value=False)

def tagged_pointer_link(tag):
    return (tag >> 1) & ~0x3

def tagged_pointer_next(ea, tp, end=None):
    assert ea
    # First try to get the offset to the next link.
    if tp:
        link_offset = tagged_pointer_link(tagged_pointer_tag(tp))
        if link_offset:
            return ea + link_offset
        # Skip the current tagged pointer in preparation for scanning.
        ea += idau.WORD_SIZE
    # We don't have a link. Do a forward scan until we find the next tagged pointer.
    _log(3, 'Scanning for next tagged pointer')
    if end is None:
        end = idc.SegEnd(ea)
    for value, value_ea in idau.ReadWords(ea, end, step=4, addresses=True):
        if is_tagged_pointer(value):
            return value_ea
    # If we didn't find any tagged pointers at all, return None.
    return None

def untag_pointer(ea, tp):
    _log(4, 'Untagging pointer at {:x}', ea)
    idau.patch_word(ea, tagged_pointer_untag(tp))
    idc.OpOff(ea, 0, 0)

def untag_pointers_in_range(start, end):
    assert kernel.kernelcache_format == kernel.KC_12_MERGED, 'Wrong kernelcache format'
    ea, tp = start, None
    while True:
        ea = tagged_pointer_next(ea, tp, end)
        if ea is None or ea >= end:
            break
        tp = idau.read_word(ea)
        if not is_tagged_pointer(tp):
            _log(1, 'Tagged pointer traversal failed: ea={:x}, tp={:x}'.format(ea, tp))
            break
        untag_pointer(ea, tp)

def untag_pointers():
    _log(2, 'Starting tagged pointer conversion')
    for seg in idautils.Segments():
        untag_pointers_in_range(idc.SegStart(seg), idc.SegEnd(seg))
    _log(2, 'Tagged pointer conversion complete')

