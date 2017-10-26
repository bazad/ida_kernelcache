#
# ida_kernelcache/kernelcache_vtable_symbols.py
# Brandon Azad
#
# Process C++ virtual method tables in a kernelcache.
#

from ida_utilities import *

import re

from kernelcache_class_info import (kernelcache_vtables, kernelcache_collect_class_info)
from kernelcache_vtable_utilities import (kernelcache_vtable_length,
        kernelcache_convert_vtable_to_offsets)
from kernelcache_vtable_methods import kernelcache_vtable_overrides
from kernelcache_stubs import kernelcache_symbol_references_stub

_log = make_log(1, 'kernelcache_vtable_symbols')

def kernelcache_vtable_symbol_for_class(classname):
    """Get the symbol name for the vtable for the given class name.

    Arguments:
        classname: The name of the C++ class.

    Returns:
        The symbol name, or None if the classname is invalid.
    """
    scopes = classname.split('::')
    symbol = '__ZTV'
    if len(scopes) > 1:
        symbol += 'N'
    for name in scopes:
        if len(name) == 0:
            return None
        symbol += '{}{}'.format(len(name), name)
    if len(scopes) > 1:
        symbol += 'E'
    return symbol

def kernelcache_add_vtable_symbol(vtable, classname):
    """Add a symbol for the virtual method table at the specified address.

    Arguments:
        vtable: The address of the virtual method table.
        classname: The name of the C++ class with this virtual method table.

    Returns:
        True if the data was successfully converted into a vtable and the symbol was added.
    """
    vtable_symbol = kernelcache_vtable_symbol_for_class(classname)
    if not set_ea_name(vtable, vtable_symbol):
        _log(0, 'Address {:#x} already has name {} instead of vtable symbol {}'
                .format(vtable, get_ea_name(vtable), vtable_symbol))
        return False
    return True

def kernelcache_add_vtable_symbols():
    """Populate IDA with virtual method table information for an iOS kernelcache.

    Search through the kernelcache for virtual method tables, convert each virtual method table
    into a sequence of offsets, and add a symbol for each identified virtual method table.
    """
    class_info_map = kernelcache_collect_class_info()
    for vtable in kernelcache_vtables:
        if not kernelcache_convert_vtable_to_offsets(vtable):
            _log(0, 'Could not convert vtable at address {:x} into offsets', vtable)
    for classname, classinfo in class_info_map.items():
        if classinfo.vtable:
            _log(3, 'Class {} has vtable at {:#x}', classname, classinfo.vtable)
            if not kernelcache_add_vtable_symbol(classinfo.vtable, classname):
                _log(0, 'Could not add vtable symbol for class {} at address {:#x}', classname,
                        classinfo.vtable)
        else:
            _log(0, 'Class {} has no known vtable', classname)

def kernelcache_class_from_vtable_method_symbol(method_symbol):
    """Get the base class in a vtable method symbol.

    Extract the name of the base class from a canonical method symbol.
    """
    demangled = idc.Demangle(method_symbol, idc.GetLongPrm(idc.INF_SHORT_DN))
    if not demangled:
        return None
    classname = demangled.split('::', 1)[0]
    if classname == demangled:
        return None
    return classname

def _kernelcache_vtable_method_symbol_substitute_class(method_symbol, new_class, old_class=None):
    """Create a new method symbol by substituting the class to which the method belongs."""
    if not old_class:
        old_class = kernelcache_class_from_vtable_method_symbol(method_symbol)
        if not old_class:
            return None
    old_class_part = '{}{}'.format(len(old_class), old_class)
    new_class_part = '{}{}'.format(len(new_class), new_class)
    if old_class_part not in method_symbol:
        return None
    return method_symbol.replace(old_class_part, new_class_part, 1)

_ignore_vtable_methods = (
    '___cxa_pure_virtual'
)

def _ok_to_rename_method(override, name):
    """Some method names are ok to rename."""
    return (name.startswith('j_') and iterlen(idautils.XrefsTo(override)) == 1)

def _bad_name_dont_use_as_override(name):
    """Some names shouldn't propagate into vtable symbols."""
    # Ignore jumps and stubs and fixed known special values.
    return (name.startswith('j_') or kernelcache_symbol_references_stub(name)
            or name in _ignore_vtable_methods)

def _symbolicate_overrides_for_classinfo(classinfo, processed):
    """A recursive function to symbolicate vtable overrides for a class and its superclasses."""
    # If we've already been processed, stop.
    if classinfo in processed:
        return
    # First propagate symbol information to our superclass.
    if classinfo.superclass:
        _symbolicate_overrides_for_classinfo(classinfo.superclass, processed)
    # Now symbolicate the superclass.
    for _, override, original in kernelcache_vtable_overrides(classinfo.classname, methods=True):
        # Skip this method if the override already has a name and we can't rename it.
        override_name = get_ea_name(override, username=True)
        if override_name and not _ok_to_rename_method(override, override_name):
            continue
        # Skip this method if the original does not have a name or if it's a bad name.
        original_name = get_ea_name(original, username=True)
        if not original_name or _bad_name_dont_use_as_override(original_name):
            continue
        # Get the new override name if we substitute for the override class's name.
        new_name = _kernelcache_vtable_method_symbol_substitute_class(original_name,
                classinfo.classname)
        if not new_name:
            _log(0, 'Could not substitute class {} into method symbol {} for override {:#x}',
                    classinfo.classname, original_name, override)
            continue
        # Now that we have the new name, set it.
        if override_name:
            _log(2, 'Renaming {} -> {}', override_name, new_name)
        if not set_ea_name(override, new_name, rename=True):
            _log(0, 'Could not set name {} for method {:#x}', new_name, override)
    # We're done.
    processed.add(classinfo)

def kernelcache_symbolicate_vtable_overrides():
    """Symbolicate overridden methods in a virtual method table.

    Propagate symbol names from the virtual method tables of the base classes."""
    processed = set()
    class_info_map = kernelcache_collect_class_info()
    for classinfo in class_info_map.values():
        _symbolicate_overrides_for_classinfo(classinfo, processed)

