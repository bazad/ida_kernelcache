#
# ida_kernelcache/__init__.py
# Brandon Azad
#
# The main ida_kernelcache module containing my iOS kernelcache utilities for IDA.
#

# This isn't kernelcache-specific, but it's useful to have access to in the interpreter and other
# scripts.
import ida_utilities

import class_struct
import classes
import kernel
import kplist
import metaclass
import offset
import segment
import stub
import vtable

from classes import (ClassInfo, collect_class_info, class_info)
from kplist  import (kplist_parse)
from segment import (kernelcache_kext)

def kernelcache_process():
    """Process the kernelcache in IDA for the first time.

    This function performs all the standard processing available in this module:
        * Renames segments in IDA according to the names from the __PRELINK_INFO dictionary.
        * Locates virtual method tables, converts them to offsets, and adds vtable symbols.
        * Locates OSMetaClass instances for top-level classes and adds OSMetaClass symbols.
        * Converts __got sections into offsets and automatically renames them.
        * Converts __stubs sections into stub functions and automatically renames them.
        * Symbolicates virtual method tables based on the method names in superclasses.
        * Creates IDA structs representing the C++ classes in the kernel.
    """
    import idc
    def autoanalyze():
        print 'Waiting for IDA autoanalysis...'
        idc.Wait()
    autoanalyze()
    # NOTE: Renaming the segments in IDA via segment.initialize_segments() is necessary for some of
    # the other functions, which rely on the more detailed segment names.
    segment.initialize_segments()
    offset.initialize_data_offsets()
    autoanalyze()
    vtable.initialize_vtables()
    autoanalyze()
    vtable.initialize_vtable_symbols()
    autoanalyze()
    metaclass.initialize_metaclass_symbols()
    offset.initialize_offset_symbols()
    autoanalyze()
    stub.initialize_stub_symbols()
    autoanalyze()
    vtable.initialize_vtable_method_symbols()
    class_struct.initialize_vtable_structs()
    class_struct.initialize_class_structs()
    print 'Done'

