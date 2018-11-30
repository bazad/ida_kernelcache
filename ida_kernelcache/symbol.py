#
# ida_kernelcache/symbol.py
# Brandon Azad
#
"""ida_kernelcache.class_struct

This module deals with processing and transforming symbol strings. It does not modify IDA.

TODO: A lot of functions in this module really have to do with processing type strings, not symbol
strings.
"""

import re

import idc
import idaapi

def method_name(symbol):
    """Get the name of the C++ method from its symbol.

    If the symbol demangles to 'Class::method(args)', this function returns 'method'.
    """
    try:
        demangled  = idc.Demangle(symbol, idc.GetLongPrm(idc.INF_SHORT_DN))
        func       = demangled.split('::', 1)[1]
        base       = func.split('(', 1)[0]
        return base or None
    except:
        return None

def method_arguments_string(symbol):
    """Get the arguments string of the C++ method from its symbol.

    If the symbol demangles to 'Class::method(arg1, arg2)', this function returns 'arg1, arg2'.
    """
    try:
        demangled  = idc.Demangle(symbol, idc.GetLongPrm(idc.INF_LONG_DN))
        func       = demangled.split('::', 1)[1]
        args       = func.split('(', 1)[1]
        args       = args.rsplit(')', 1)[0].strip()
        return args
    except:
        return None

def method_arguments(symbol):
    """Get the arguments list of the C++ method from its symbol.

    If the symbol demangles to 'Class::method(arg1, arg2)', this function returns ['arg1', 'arg2'].
    """
    try:
        arglist = []
        args = method_arguments_string(symbol)
        if args is None:
            return None
        if not args or args == 'void':
            return arglist
        carg = ''
        parens = 0
        for c in args + ',':
            if c == ',' and parens == 0:
                carg = carg.strip()
                assert carg
                arglist.append(carg)
                carg = ''
                continue
            if c == '(':
                parens += 1
            elif c == ')':
                parens -= 1
            carg += c
        return arglist
    except:
        return None

def method_argument_pointer_types(symbol):
    """Get the base types of pointer types used in the arguments to a C++ method."""
    args = method_arguments_string(symbol)
    if args is None:
        return None
    if not args or args == 'void':
        return set()
    args = re.sub(r"[&]|\bconst\b", ' ', args)
    args = re.sub(r"\bunsigned\b", ' ', args)
    args = re.sub(r" +", ' ', args)
    argtypes = set(arg.strip() for arg in re.split(r"[,()]", args))
    ptrtypes = set()
    for argtype in argtypes:
        if re.match(r"[^ ]+ [*][* ]*", argtype):
            ptrtypes.add(argtype.split(' ', 1)[0])
    ptrtypes.difference_update(['void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double',
        'longlong', '__int64'])
    return ptrtypes

def method_argument_types(symbol, sign=True):
    """Get the base types used in the arguments to a C++ method."""
    try:
        args = method_arguments_string(symbol)
        if args is None:
            return None
        if not args or args == 'void':
            return set()
        args = re.sub(r"[*&]|\bconst\b", ' ', args)
        if not sign:
            args = re.sub(r"\bunsigned\b", ' ', args)
        args = re.sub(r" +", ' ', args)
        argtypes = set(arg.strip() for arg in re.split(r"[,()]", args))
        argtypes.discard('')
        return argtypes
    except:
        return None

def convert_function_type_to_function_pointer_type(typestr):
    """Convert a function type string into a function pointer type string.

    For example:
        __int64 __fastcall(arg1, arg2) => __int64 __fastcall (*)(arg1, arg2)
    """
    try:
        return_part, args_part = typestr.split('(', 1)
        return return_part + ' (*)(' + args_part
    except:
        return None

def make_ident(name):
    """Convert a name into a valid identifier, substituting any invalid characters."""
    ident = ''
    for c in name:
        if idaapi.is_ident_char(ord(c)):
            ident += c
        else:
            ident += '_'
    return ident

def _mangle_name(scopes):
    symbol = ''
    if len(scopes) > 1:
        symbol += 'N'
    for name in scopes:
        if len(name) == 0:
            return None
        symbol += '{}{}'.format(len(name), name)
    if len(scopes) > 1:
        symbol += 'E'
    return symbol

def vtable_symbol_for_class(classname):
    """Get the mangled symbol name for the vtable for the given class name.

    Arguments:
        classname: The name of the C++ class.

    Returns:
        The symbol name, or None if the classname is invalid.
    """
    name = _mangle_name(classname.split('::'))
    if not name:
        return None
    return '__ZTV' + name

def vtable_symbol_get_class(symbol):
    """Get the class name for a vtable symbol."""
    try:
        demangled = idc.Demangle(symbol, idc.GetLongPrm(idc.INF_SHORT_DN))
        pre, post = demangled.split("`vtable for'", 1)
        assert pre == ''
        return post
    except:
        return None

def global_name(name):
    """Get the mangled symbol name for the global name.

    Arguments:
        name: The name of the global object.

    Returns:
        The symbol name, or None if the name is invalid.
    """
    mangled = _mangle_name(name.split('::'))
    if not mangled:
        return None
    return '__Z' + mangled

