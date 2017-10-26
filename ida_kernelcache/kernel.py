#
# ida_kernelcache/kernel.py
# Brandon Azad
#
# The kernel module holds functions and global variables pertaining to the kernel as a whole. No
# prior initialization via ida_kernelcache is necessary.
#

import idc
import idautils
import idaapi

import ida_utilities as idau
import kplist

_log = idau.make_log(0, __name__)

def find_kernel_base():
    """Find the kernel base."""
    return idaapi.get_fileregion_ea(0)

base = find_kernel_base()
"""The kernel base address (the address of the main kernel Mach-O header)."""

def _find_prelink_info_segment():
    """Find the __PRELINK_INFO segment.

    We try to identify a unique segment with __PRELINK_INFO in the name so that this function will
    work both before and after automatic rename. A more reliable method would be parsing the
    Mach-O.
    """
    segments = []
    for seg in idautils.Segments():
        name = idc.SegName(seg)
        if '__PRELINK_INFO' in name:
            segments.append(seg)
    if len(segments) < 1:
        _log(0, 'No segment name contains __PRELINK_INFO')
    elif len(segments) > 1:
        _log(0, 'Multiple segment names contain __PRELINK_INFO: {}',
                [idc.SegName(seg) for seg in segments])
    else:
        return segments[0]
    return None

def parse_prelink_info():
    """Find and parse the kernel __PRELINK_INFO dictionary."""
    segment = _find_prelink_info_segment()
    if not segment:
        return None
    prelink_info_string = idc.GetString(segment)
    return kplist.kplist_parse(prelink_info_string)

prelink_info = parse_prelink_info()
"""The kernel __PRELINK_INFO dictionary."""

