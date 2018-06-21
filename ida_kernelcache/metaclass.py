#
# ida_kernelcache/metaclass.py
# Brandon Azad
#
# A module for working with OSMetaClass instances in the kernelcache.
#

import idc

import ida_utilities as idau
import classes
import symbol

_log = idau.make_log(0, __name__)

def metaclass_name_for_class(classname):
    """Return the name of the C++ metaclass for the given class."""
    if '::' in classname:
        return None
    return classname + '::MetaClass'

def metaclass_instance_name_for_class(classname):
    """Return the name of the C++ metaclass instance for the given class."""
    if '::' in classname:
        return None
    return classname + '::gMetaClass'

def metaclass_symbol_for_class(classname):
    """Get the symbol name for the OSMetaClass instance for the given class name.

    Arguments:
        classname: The name of the C++ class.

    Returns:
        The symbol name, or None if the classname is invalid.
    """
    metaclass_instance = metaclass_instance_name_for_class(classname)
    if not metaclass_instance:
        return None
    return symbol.global_name(metaclass_instance)

def add_metaclass_symbol(metaclass, classname):
    """Add a symbol for the OSMetaClass instance at the specified address.

    Arguments:
        metaclass: The address of the OSMetaClass instance.
        classname: The name of the C++ class with this OSMetaClass instance.

    Returns:
        True if the OSMetaClass instance's symbol was created successfully.
    """
    metaclass_symbol = metaclass_symbol_for_class(classname)
    if not idau.set_ea_name(metaclass, metaclass_symbol):
        _log(0, 'Address {:#x} already has name {} instead of OSMetaClass instance symbol {}'
                .format(metaclass, idau.get_ea_name(metaclass), metaclass_symbol))
        return False
    return True

def initialize_metaclass_symbols():
    """Populate IDA with OSMetaClass instance symbols for an iOS kernelcache.

    Search through the kernelcache for OSMetaClass instances and add a symbol for each known
    instance.
    """
    classes.collect_class_info()
    for classname, classinfo in classes.class_info.items():
        if classinfo.metaclass:
            _log(1, 'Class {} has OSMetaClass instance at {:#x}', classname, classinfo.metaclass)
            if not add_metaclass_symbol(classinfo.metaclass, classname):
                _log(0, 'Could not add metaclass symbol for class {} at address {:#x}', classname,
                        classinfo.metaclass)
        else:
            _log(1, 'Class {} has no known OSMetaClass instance', classname)

