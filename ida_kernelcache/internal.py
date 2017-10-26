#
# ida_kernelcache/internal.py
# Brandon Azad
#
# Miscellaneous internal routines.
#

from collections import defaultdict

import idc

import ida_utilities as idau

def make_name_generator(suffix, max_count=999999):
    """Create a unique name generator using the specified template factory."""
    next_index_dict = defaultdict(lambda: 1)
    def get_next(name):
        assert name, 'Invalid symbol name passed to name generator'
        assert suffix not in name, 'Symbol name passed to name generator already contains suffix'
        template = name + suffix
        for index in xrange(next_index_dict[name], max_count):
            new_name = template + str(index)
            if idau.get_name_ea(new_name) == idc.BADADDR:
                next_index_dict[name] = index
                return new_name
        new_index_dict[name] = max_count
        return None
    return get_next

