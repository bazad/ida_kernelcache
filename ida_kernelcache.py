#
# ida_kernelcache.py
# Brandon Azad
#
# Entry point for my iOS kernelcache utilities for IDA.
#

from kernelcache_vtable_utilities import (VTABLE_OFFSET, kernelcache_vtable_length,
        kernelcache_convert_vtable_to_offsets)

from kernelcache_class_info import (ClassInfo, kernelcache_class_info,
        kernelcache_collect_class_info)

from kernelcache_vtable_symbols import (kernelcache_vtable_symbol_for_class,
        kernelcache_add_vtable_symbol, kernelcache_add_vtable_symbols)

from kernelcache_metaclass_symbols import (kernelcache_metaclass_name_for_class,
        kernelcache_metaclass_instance_name_for_class, kernelcache_metaclass_symbol_for_class,
        kernelcache_add_metaclass_symbol, kernelcache_add_metaclass_symbols)

def kernelcache_process():
    """Process the kernelcache in IDA.

    This function performs all the standard processing available in this module, including:
        * Locating virtual method tables, converting them to offsets, and adding symbols.
        * Locating OSMetaClass instances for top-level classes and adding symbols.
    """
    kernelcache_add_vtable_symbols()
    kernelcache_add_metaclass_symbols()

