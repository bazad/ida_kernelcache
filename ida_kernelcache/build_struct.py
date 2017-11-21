#
# ida_kernelcache/build_struct.py
# Brandon Azad
#
# A module to build an IDA structure automatically from code accesses.
#

import collections

import idc
import idautils
import idaapi

import ida_utilities as idau

_log = idau.make_log(3, __name__)

def field_name(offset):
    """Automatically generated IDA structs have their fields named by their absolute offset."""
    return 'field_{:x}'.format(offset)

def create_struct_fields(sid=None, name=None, accesses=None, create=False, base=0):
    """Create an IDA struct with fields corresponding to the specified access pattern.

    Given a sequence of (offset, size) tuples designating the valid access points to the struct,
    create fields in the struct at the corresponding positions.

    Options:
        sid: The struct id, if the struct already exists.
        name: The name of the struct to update or create.
        accesses: The set of (offset, size) tuples representing the valid access points in the
            struct.
        create: If True, then the struct will be created with the specified name if it does not
            already exist. Default is False.
        base: The base offset for the struct. Offsets smaller than this are ignored, otherwise the
            field is created at the offset minus the base. Default is 0.

    Either sid or name must be specified.
    """
    # Get the struct id.
    if sid is None:
        sid = idau.struct_open(name, create=True)
        if sid is None:
            _log(0, 'Could not open struct {}', name)
            return False
    else:
        name = idc.GetStrucName(sid)
        if name is None:
            _log(0, 'Invalid struct id {}', sid)
            return False
    # Now, for each (offset, size) pair, create a struct member. Right now we completely ignore the
    # possibility that some members will overlap (for various reasons; it's actually more common
    # than I initially thought, though I haven't investigated why).
    # TODO: In the future we should address this by either automatically generating sub-unions or
    # choosing the most appropriate member when permissible (e.g. (0, 8), (0, 2), (4, 4) might
    # create (0, 2), (2, 2), (4, 4)). I think the most reasonable default policy is to create the
    # biggest members that satisfy all accesses.
    success = True
    for offset, size in accesses:
        if offset < base:
            continue
        member = field_name(offset)
        ret = idau.struct_add_word(sid, member, offset - base, size)
        if ret != 0:
            if ret == idc.STRUC_ERROR_MEMBER_OFFSET:
                _log(2, 'Could not add {}.{} for access ({}, {})', name, member, offset, size)
            else:
                success = False
                _log(1, 'Could not add {}.{} for access ({}, {}): {}', name, member, offset, size,
                        ret)
    return success

