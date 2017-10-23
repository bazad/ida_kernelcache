#
# ida_kernelcache.py
# Brandon Azad
#
# Entry point for my iOS kernelcache utilities for IDA.
#

import idc

from kplist import (kplist_parse)

from kernelcache_ida_segments import (kernelcache_kernel_base, kernelcache_initialize_segments,
        kernelcache_kext)

from kernelcache_offsets import (kernelcache_data_offsets)

from kernelcache_vtable_utilities import (VTABLE_OFFSET, kernelcache_vtable_length,
        kernelcache_convert_vtable_to_offsets)

from kernelcache_class_info import (ClassInfo, kernelcache_class_info, kernelcache_vtables,
        kernelcache_collect_class_info)

from kernelcache_vtable_symbols import (kernelcache_vtable_symbol_for_class,
        kernelcache_add_vtable_symbol, kernelcache_add_vtable_symbols)

from kernelcache_metaclass_symbols import (kernelcache_metaclass_name_for_class,
        kernelcache_metaclass_instance_name_for_class, kernelcache_metaclass_symbol_for_class,
        kernelcache_add_metaclass_symbol, kernelcache_add_metaclass_symbols)

from kernelcache_stubs import (kernelcache_offset_name_target, kernelcache_stub_name_target,
        kernelcache_symbol_references_stub, kernelcache_stub_target,
        kernelcache_symbolicate_offsets, kernelcache_symbolicate_stubs)

from kernelcache_vtable_methods import (kernelcache_vtable_overrides)

def kernelcache_process():
    """Process the kernelcache in IDA.

    This function performs all the standard processing available in this module:
        * Renames segments in IDA according to the names from the __PRELINK_INFO dictionary.
        * Locates virtual method tables, converts them to offsets, and adds vtable symbols.
        * Locates OSMetaClass instances for top-level classes and adds OSMetaClass symbols.
        * Converts __got sections into offsets and automatically renames them.
        * Converts __stubs sections into stub functions and automatically renames them.
    """
    def autoanalyze():
        print 'Waiting for IDA autoanalysis...'
        idc.Wait()
    autoanalyze()
    # NOTE: Renaming the segments in IDA via kernelcache_initialize_segments() is necessary for
    # some of the other functions, which rely on the more detailed segment names.
    kernelcache_initialize_segments()
    kernelcache_data_offsets()
    autoanalyze()
    kernelcache_add_vtable_symbols()
    autoanalyze()
    kernelcache_add_metaclass_symbols()
    kernelcache_symbolicate_offsets()
    autoanalyze()
    kernelcache_symbolicate_stubs()
    autoanalyze()
    print 'Done'

