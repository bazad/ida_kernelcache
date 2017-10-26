#
# ida_kernelcache/kernelcache_offsets.py
# Brandon Azad
#
# Convert offsets in data segments into offsets in IDA.
#

from ida_utilities import *

def kernelcache_data_offsets():
    """Convert offsets in data segments into offsets in IDA."""
    # Normally, for user-space programs, this operation would be dangerous because there's a good
    # chance that a valid userspace address would happen to show up in regular program data that is
    # not actually an address. However, since kernel addresses are numerically much larger, the
    # chance of this happening is much less.
    for seg in idautils.Segments():
        name = idc.SegName(seg)
        if not (name.endswith('__DATA_CONST.__const') or name.endswith('__got')
                or name.endswith('__DATA.__data')):
            continue
        for word, ea in ReadWords(seg, idc.SegEnd(seg), addresses=True):
            if is_mapped(word, value=False):
                idc.OpOff(ea, 0, 0)

