#
# kernelcache_vtable_symbols.py
# Brandon Azad
#

from ida_utilities import *
from kernelcache_class_info import *
from kernelcache_vtable_utilities import *

_kernelcache_vtable_symbols__log_level = 1

def _log(level, fmt, *args):
    if level <= _kernelcache_vtable_symbols__log_level:
        print 'kernelcache_vtable_symbols: ' + fmt.format(*args)

def kernelcache_vtable_symbol_for_class(classname):
    """Get the symbol name for the vtable for the given class name.

    Arguments:
        classname: The name of the C++ class.

    Returns:
        The symbol name, or None if the classname is invalid.
    """
    symbol = '__ZTV'
    scopes = classname.split('::')
    if len(scopes) > 1:
        symbol += 'N'
    for name in scopes:
        if len(name) == 0:
            return None
        symbol += '{}{}'.format(len(name), name)
    if len(scopes) > 1:
        symbol += 'E'
    return symbol

def kernelcache_add_vtable_symbol(vtable, classname, make_offsets=True):
    """Add a symbol for the virtual method table at the specified address.

    Arguments:
        vtable: The address of the virtual method table.
        classname: The name of the C++ class with this virtual method table.

    Returns:
        True if the data was successfully converted into a vtable and the symbol was added.
    """
    if make_offsets and not kernelcache_convert_vtable_to_offsets(vtable):
        return False
    vtable_symbol = kernelcache_vtable_symbol_for_class(classname)
    if hasUserName(GetFlags(vtable)):
        current_name = NameEx(BADADDR, vtable)
        if current_name != vtable_symbol:
            _log(0, 'Address {:#x} already has name {} instead of vtable symbol {}'
                    .format(vtable, current_name, vtable_symbol))
            return False
    else:
        MakeName(vtable, vtable_symbol)
    return True


def kernelcache_add_vtable_symbols():
    """Populate IDA with virtual method table information for an iOS kernelcache.

    Search through the kernelcache for virtual method tables and add symbols
    """
    class_info_map = kernelcache_collect_class_info()
    for classname, classinfo in class_info_map.items():
        _log(1, 'Class {} has vtable at {:#x}', classname, classinfo.vtable)
        if not kernelcache_add_vtable_symbol(classinfo.vtable, classname):
            _log(0, 'Could not add vtable for class {} at address {:#x}', classname,
                    classinfo.vtable)

