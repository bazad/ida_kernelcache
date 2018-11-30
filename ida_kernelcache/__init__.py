#
# ida_kernelcache/__init__.py
# Brandon Azad
#
# The main ida_kernelcache module containing my iOS kernelcache utilities for IDA.
#

# This isn't kernelcache-specific, but it's useful to have access to in the interpreter and other
# scripts.
import ida_utilities

import build_struct
import class_struct
import classes
import kernel
import kplist
import metaclass
import offset
import segment
import stub
import tagged_pointers
import vtable

from classes import (ClassInfo, collect_class_info, class_info)
from kplist  import (kplist_parse)
from segment import (kernelcache_kext)

def kernelcache_process(untag_pointers=True):
    """Process the kernelcache in IDA for the first time.

    This function performs all the standard processing available in this module:
        * Convert iOS 12's new static tagged pointers into normal kernel pointers.
        * Parse the kernel's `__PRELINK_INFO.__info` section into a dictionary.
        * Renames segments in IDA according to the names from the __PRELINK_INFO dictionary (split
          kext format kernelcaches only).
        * Converts pointers in data segments into offsets.
        * Locates virtual method tables, converts them to offsets, and adds vtable symbols.
        * Locates OSMetaClass instances for top-level classes and adds OSMetaClass symbols.
        * Symbolicates offsets in `__got` sections and stub functions in `__stubs` sections.
        * Symbolicates methods in vtables based on the method names in superclasses.
        * Creates IDA structs representing the C++ classes in the kernel.
    """
    import idaapi
    import idc
    def autoanalyze():
        idc.Wait()
    autoanalyze()
    if (kernel.kernelcache_format == kernel.KC_12_MERGED
            and untag_pointers
            and idaapi.IDA_SDK_VERSION < 720):
        print 'Processing tagged kernelcache pointers'
        tagged_pointers.untag_pointers()
        autoanalyze()
    segment.initialize_segments()
    print 'Initializing data offsets'
    offset.initialize_data_offsets()
    autoanalyze()
    print 'Initializing vtables'
    vtable.initialize_vtables()
    autoanalyze()
    vtable.initialize_vtable_symbols()
    autoanalyze()
    metaclass.initialize_metaclass_symbols()
    if kernel.kernelcache_format == kernel.KC_11_NORMAL:
        print 'Creating offset and stub symbols'
        offset.initialize_offset_symbols()
        autoanalyze()
        stub.initialize_stub_symbols()
        autoanalyze()
    print 'Propagating vtable method symbols'
    vtable.initialize_vtable_method_symbols()
    print 'Initializing class structs'
    class_struct.initialize_vtable_structs()
    class_struct.initialize_class_structs()
    autoanalyze()
    print 'Done'

