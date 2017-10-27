#
# ida_kernelcache/vtable.py
# Brandon Azad
#
# Functions for analyzing and symbolicating vtables in the kernelcache.
#

from itertools import islice, takewhile

import idc
import idautils

import ida_utilities as idau
import classes
import stub

_log = idau.make_log(0, __name__)

VTABLE_OFFSET      =  2
"""The first few entries of the virtual method tables in the kernelcache are empty."""
MIN_VTABLE_METHODS = 12
"""The minimum number of methods in a virtual method table."""
MIN_VTABLE_LENGTH  = VTABLE_OFFSET + MIN_VTABLE_METHODS
"""The minimum length of a virtual method table in words, including the initial empty entries."""

def vtable_length(ea, end=None, scan=False):
    """Find the length of a virtual method table.

    This function checks whether the effective address could correspond to a virtual method table
    and returns its length, including the initial empty entries.

    Arguments:
        ea: The linear address of the start of the vtable.

    Options:
        end: The end address to search through. Defaults to the end of the section.
        scan: As a slight optimization when using this function to scan for vtables, setting scan
            to True will cause this function to look ahead in some cases to increase the amount of
            data that can be skipped, reducing duplication of effort between subsequent calls.

    Returns:
        A tuple (possible, length). If the address could correspond to the start of a vtable, then
        possible is True and length is the length of the vtable in words, including the initial
        empty entries. Otherwise, if the address is definitely not the start of a vtable, then
        possible is False and length is the number of words that can be skipped when searching for
        the next vtable.
    """
    if end is None:
        end = idc.SegEnd(ea)
    words = idau.ReadWords(ea, end)
    # Iterate through the first VTABLE_OFFSET words. If any of them are nonzero, then we can skip
    # past all the words we just saw.
    for idx, word in enumerate(islice(words, VTABLE_OFFSET)):
        if word != 0:
            return False, idx + 1
    # Now this first word after the padding section is special.
    first = next(words, None)
    if first is None:
        # We have 2 zeros followed by the end of our range.
        return False, VTABLE_OFFSET
    elif first == 0:
        # We have VTABLE_OFFSET + 1 zero entries.
        zeros = VTABLE_OFFSET + 1
        if scan:
            # To avoid re-reading the data we just read in the case of a zero-filled section, let's
            # look ahead a bit until we find the first non-zero value.
            for word in words:
                if word is None:
                    return False, zeros
                if word != 0:
                    break
                zeros += 1
            else:
                # We found no nonzero words before the end.
                return False, zeros
        # We can skip all but the last VTABLE_OFFSET zeros.
        return False, zeros - VTABLE_OFFSET
    # TODO: We should verify that all vtable entries refer to code.
    # Now we know that we have at least one nonzero value, our job is easier. Get the full length
    # of the vtable, including the first VTABLE_OFFSET entries and the subsequent nonzero entries,
    # until either we find a zero word (not included) or run out of words in the stream.
    length = VTABLE_OFFSET + 1 + idau.iterlen(takewhile(lambda word: word != 0, words))
    # Now it's simple: We are valid if the length is long enough, invalid if it's too short.
    return length >= MIN_VTABLE_LENGTH, length

def convert_vtable_to_offsets(vtable):
    """Convert a vtable into a sequence of offsets.

    Arguments:
        vtable: The address of the virtual method table.

    Returns:
        True if the data was successfully converted into offsets.
    """
    possible, length = vtable_length(vtable)
    if not possible:
        _log(0, 'Address {:#x} is not a vtable', vtable)
        return False
    successful = True
    for address in idau.Addresses(vtable, length=length, step=idau.WORD_SIZE):
        if not idc.OpOff(address, 0, 0):
            _log(0, 'Could not change address {:#x} into an offset', address)
            successful = False
    return successful

def vtable_symbol_for_class(classname):
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

def add_vtable_symbol(vtable, classname):
    """Add a symbol for the virtual method table at the specified address.

    Arguments:
        vtable: The address of the virtual method table.
        classname: The name of the C++ class with this virtual method table.

    Returns:
        True if the data was successfully converted into a vtable and the symbol was added.
    """
    vtable_symbol = vtable_symbol_for_class(classname)
    if not idau.set_ea_name(vtable, vtable_symbol):
        _log(0, 'Address {:#x} already has name {} instead of vtable symbol {}'
                .format(vtable, idau.get_ea_name(vtable), vtable_symbol))
        return False
    return True

def initialize_vtable_symbols():
    """Populate IDA with virtual method table information for an iOS kernelcache.

    Search through the kernelcache for virtual method tables, convert each virtual method table
    into a sequence of offsets, and add a symbol for each identified virtual method table.
    """
    class_info_map = classes.collect_class_info()
    for vtable in classes.vtables:
        if not convert_vtable_to_offsets(vtable):
            _log(0, 'Could not convert vtable at address {:x} into offsets', vtable)
    for classname, classinfo in class_info_map.items():
        if classinfo.vtable:
            _log(3, 'Class {} has vtable at {:#x}', classname, classinfo.vtable)
            if not add_vtable_symbol(classinfo.vtable, classname):
                _log(0, 'Could not add vtable symbol for class {} at address {:#x}', classname,
                        classinfo.vtable)
        else:
            _log(0, 'Class {} has no known vtable', classname)

def vtable_methods(vtable, length=None):
    """Get the methods in a virtual method table.

    A generator that returns each method in the virtual method table. The initial empty entries are
    skipped.

    Arguments:
        vtable: The address of the virtual method table. (This includes the initial empty entries.)

    Options:
        length: The number of methods to read, excluding the initial empty entries. If None, the
            whole vtable will be read. Default is None.
    """
    # First, get the correct length.
    if length is None:
        possible, length = vtable_length(vtable)
        if not possible:
            return
    else:
        length += VTABLE_OFFSET
    # Read the methods.
    for i in xrange(VTABLE_OFFSET, length):
        yield idau.read_word(vtable + i * idau.WORD_SIZE)

def vtable_overrides(classinfo=None, classname=None, superinfo=None, new=False, methods=False):
    """Get the overrides of a virtual method table.

    A generator that returns the index of each override in the virtual method table. The index
    excludes the initial empty entries of the vtable.

    Options:
        classinfo: The ClassInfo of the class to inspect.
        classname: The name of the class to inspect.
        superinfo: The ClassInfo of the ancestor to compare against for overrides. If None, then
            the ClassInfo of the direct superclass will be used. Default is None.
        new: If True, include new virtual methods not present in the superclass. Default is False.
        methods: If True, then the generator will produce a tuple containing the index, the
            overridden method in the subclass, and the original method in the superclas, rather
            than just the index. Default is False.

    Exactly one of classinfo and classname must be specified.
    """
    # First, get the correct classinfo.
    if classinfo is None:
        if classname is None:
            raise ValueError('Invalid arguments: classinfo={}, classname={}'.format(classinfo,
                classname))
        class_info_map = classes.collect_class_info()
        classinfo = class_info_map[classname]
    elif classname is not None and classinfo.classname != classname:
        raise ValueError('Invalid arguments: classinfo={}, classname={}'.format(classinfo,
            classname))
    # Now get the correct superinfo.
    if superinfo is None:
        # Default to the superclass, but if there isn't one, there's nothing to do.
        superinfo = classinfo.superclass
        if not superinfo:
            return
    else:
        if superinfo not in classinfo.ancestors():
            raise ValueError('Invalid arguments: classinfo={}, superinfo={}'.format(classinfo,
                superinfo))
    # Get the vtable for the class.
    class_vtable = classinfo.vtable
    possible, class_vtable_length = vtable_length(class_vtable)
    assert possible, 'Class {} has invalid vtable {:#x}'.format(classname, class_vtable)
    # Get the vtable for the superclass.
    super_vtable = superinfo.vtable
    possible, super_vtable_length = vtable_length(super_vtable)
    assert possible, 'Class {} has invalid vtable {:#x}'.format(superinfo.classname, super_vtable)
    assert class_vtable_length >= super_vtable_length
    # How many methods are we iterating over?
    nmethods = super_vtable_length
    if new and class_vtable_length > nmethods:
        nmethods = class_vtable_length
    # Skip the first VTABLE_OFFSET entries.
    class_vtable += VTABLE_OFFSET * idau.WORD_SIZE
    super_vtable += VTABLE_OFFSET * idau.WORD_SIZE
    nmethods     -= VTABLE_OFFSET
    # Iterate through the methods.
    for i in xrange(nmethods):
        # Read the old method.
        super_method = None
        if i < super_vtable_length:
            super_method = idau.read_word(super_vtable + i * idau.WORD_SIZE)
        # Read the new method. (It's always in range.)
        class_method = idau.read_word(class_vtable + i * idau.WORD_SIZE)
        # If they're different, yield.
        if class_method != super_method:
            if methods:
                yield i, class_method, super_method
            else:
                yield i

def class_from_vtable_method_symbol(method_symbol):
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

def _vtable_method_symbol_substitute_class(method_symbol, new_class, old_class=None):
    """Create a new method symbol by substituting the class to which the method belongs."""
    if not old_class:
        old_class = class_from_vtable_method_symbol(method_symbol)
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
    return (name.startswith('j_') and idau.iterlen(idautils.XrefsTo(override)) == 1)

def _bad_name_dont_use_as_override(name):
    """Some names shouldn't propagate into vtable symbols."""
    # Ignore jumps and stubs and fixed known special values.
    return (name.startswith('j_') or stub.symbol_references_stub(name)
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
    for _, override, original in vtable_overrides(classinfo, methods=True):
        # Skip this method if the override already has a name and we can't rename it.
        override_name = idau.get_ea_name(override, username=True)
        if override_name and not _ok_to_rename_method(override, override_name):
            continue
        # Skip this method if the original does not have a name or if it's a bad name.
        original_name = idau.get_ea_name(original, username=True)
        if not original_name or _bad_name_dont_use_as_override(original_name):
            continue
        # Get the new override name if we substitute for the override class's name.
        new_name = _vtable_method_symbol_substitute_class(original_name, classinfo.classname)
        if not new_name:
            _log(0, 'Could not substitute class {} into method symbol {} for override {:#x}',
                    classinfo.classname, original_name, override)
            continue
        # Now that we have the new name, set it.
        if override_name:
            _log(2, 'Renaming {} -> {}', override_name, new_name)
        if not idau.set_ea_name(override, new_name, rename=True):
            _log(0, 'Could not set name {} for method {:#x}', new_name, override)
    # We're done.
    processed.add(classinfo)

def initialize_vtable_method_symbols():
    """Symbolicate overridden methods in a virtual method table.

    Propagate symbol names from the virtual method tables of the base classes."""
    processed = set()
    class_info_map = classes.collect_class_info()
    for classinfo in class_info_map.values():
        _symbolicate_overrides_for_classinfo(classinfo, processed)

