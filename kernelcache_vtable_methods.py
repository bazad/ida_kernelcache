#
# kernelcache_vtable_methods.py
# Brandon Azad
#
# Functions for examining methods in virtual method tables.
#

from ida_utilities import *

from kernelcache_class_info import kernelcache_collect_class_info
from kernelcache_vtable_utilities import (VTABLE_OFFSET, kernelcache_vtable_length)

def kernelcache_vtable_overrides(classname, new=False, methods=False):
    """Get the overrides of a virtual method table.

    A generator that returns the index of each override in the virtual method table.

    Arguments:
        classname: The name of the class.

    Options:
        new: If True, include new virtual methods not present in the superclass. Default is False.
        methods: If True, then the generator will produce a tuple containing the index, the
            overridden method in the subclass, and the original method in the superclas, rather
            than just the index. Default is False.
    """
    class_info_map = kernelcache_collect_class_info()
    # Get the vtable for the class.
    class_info = class_info_map[classname]
    if not class_info.superclass_name:
        return
    class_vtable = class_info.vtable
    possible, class_vtable_length = kernelcache_vtable_length(class_vtable)
    assert possible, 'Class {} has invalid vtable {:#x}'.format(classname, class_vtable)
    # Get the vtable for the superclass.
    super_info = class_info_map[class_info.superclass_name]
    super_vtable = super_info.vtable
    possible, super_vtable_length = kernelcache_vtable_length(super_vtable)
    assert possible, 'Class {} has invalid vtable {:#x}'.format(super_info.classname, super_vtable)
    assert class_vtable_length >= super_vtable_length
    # How many methods are we iterating over?
    nmethods = super_vtable_length
    if new and class_vtable_length > nmethods:
        nmethods = class_vtable_length
    # Iterate through the methods.
    for i in xrange(VTABLE_OFFSET, nmethods):
        # Read the old method.
        super_method = None
        if i < super_vtable_length:
            super_method = read_word(super_vtable + i * WORD_SIZE)
        # Read the new method. (It's always in range.)
        class_method = read_word(class_vtable + i * WORD_SIZE)
        # If they're different, yield.
        if class_method != super_method:
            if methods:
                yield i, class_method, super_method
            else:
                yield i

