#
# kernelcache_metaclass_symbols.py
# Brandon Azad
#
# Process OSMetaClass instances in a kernelcache.
#

from ida_utilities import *

from kernelcache_class_info import kernelcache_collect_class_info

_log = make_log(0, 'kernelcache_metaclass_symbols')

def kernelcache_metaclass_name_for_class(classname):
    """Return the name of the C++ metaclass for the given class."""
    if '::' in classname:
        return None
    return classname + '::MetaClass'

def kernelcache_metaclass_instance_name_for_class(classname):
    """Return the name of the C++ metaclass instance for the given class."""
    if '::' in classname:
        return None
    return classname + '::gMetaClass'

def kernelcache_metaclass_symbol_for_class(classname):
    """Get the symbol name for the OSMetaClass instance for the given class name.

    Arguments:
        classname: The name of the C++ class.

    Returns:
        The symbol name, or None if the classname is invalid.
    """
    metaclass_instance = kernelcache_metaclass_instance_name_for_class(classname)
    if not metaclass_instance:
        return None
    scopes = metaclass_instance.split('::')
    symbol = '__Z'
    if len(scopes) > 1:
        symbol += 'N'
    for name in scopes:
        if len(name) == 0:
            return None
        symbol += '{}{}'.format(len(name), name)
    if len(scopes) > 1:
        symbol += 'E'
    return symbol

OK = False
"""Whether this module seems to be working."""

def _initialize():
    global OK
    OSObject_gMetaClass = kernelcache_metaclass_symbol_for_class("OSObject")
    if get_name_ea(OSObject_gMetaClass) == idc.BADADDR:
        _log(-1, 'Cannot locate OSMetaClass instance for OSObject; either this is not a '
                'recognized kernelcache or symbol generation is broken. Disabling module '
                'functionality.')
    else:
        OK = True

_initialize()

def _check_ok():
    """Check that these functions are OK to use."""
    if not OK:
        _log(-1, 'OSMetaClass functionality seems to be broken')
    return OK

def kernelcache_add_metaclass_symbol(metaclass, classname):
    """Add a symbol for the OSMetaClass instance at the specified address.

    Arguments:
        metaclass: The address of the OSMetaClass instance.
        classname: The name of the C++ class with this OSMetaClass instance.

    Returns:
        True if the OSMetaClass instance's symbol was created successfully.
    """
    if not _check_ok():
        return False
    metaclass_symbol = kernelcache_metaclass_symbol_for_class(classname)
    if not set_ea_name(metaclass, metaclass_symbol):
        _log(0, 'Address {:#x} already has name {} instead of OSMetaClass instance symbol {}'
                .format(metaclass, get_ea_name(metaclass), metaclass_symbol))
        return False
    return True

def kernelcache_add_metaclass_symbols():
    """Populate IDA with OSMetaClass instance symbols for an iOS kernelcache.

    Search through the kernelcache for OSMetaClass instances and add a symbol for each known
    instance.
    """
    if not _check_ok():
        return False
    class_info_map = kernelcache_collect_class_info()
    for classname, classinfo in class_info_map.items():
        if classinfo.metaclass:
            _log(1, 'Class {} has OSMetaClass instance at {:#x}', classname, classinfo.metaclass)
            if not kernelcache_add_metaclass_symbol(classinfo.metaclass, classname):
                _log(0, 'Could not add metaclass symbol for class {} at address {:#x}', classname,
                        classinfo.metaclass)
        else:
            _log(1, 'Class {} has no known OSMetaClass instance', classname)

