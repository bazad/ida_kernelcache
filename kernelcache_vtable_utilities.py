#
# kernelcache_vtable_utilities.py
# Brandon Azad
#
# Utility functions for dealing with virtual method tables.
#

from ida_utilities import *

from itertools import islice, takewhile

_log = make_log(0, 'kernelcache_vtable_utilities')

VTABLE_OFFSET      =  2
"""The first few entries of the virtual method tables in the kernelcache are empty."""
MIN_VTABLE_METHODS = 12
"""The minimum number of methods in a virtual method table."""
MIN_VTABLE_LENGTH  = VTABLE_OFFSET + MIN_VTABLE_METHODS
"""The minimum length of a virtual method table in words, including the initial empty entries."""

def kernelcache_vtable_length(ea, end=None, scan=False):
    """Find the length of a virtual method table.

    This function checks whether the effective address could correspond to a virtual method table
    and returns its length.

    Arguments:
        ea: The linear address of the start of the vtable.

    Options:
        end: The end address to search through. Defaults to the end of the section.
        scan: As a slight optimization when using this function to scan for vtables, setting scan
            to True will cause this function to look ahead in some cases to increase the amount of
            data that can be skipped, reducing duplication of effort between subsequent calls.

    Returns:
        A tuple (possible, length). If the address could correspond to the start of a vtable, then
        possible is True and length is the length of the vtable in words. Otherwise, if the address
        is definitely not the start of a vtable, then possible is False and length is the number of
        words that can be skipped when searching for the next vtable.
    """
    if end is None:
        end = idc.SegEnd(ea)
    words = ReadWords(ea, end)
    # Iterate through the first VTABLE_OFFSET words. If any of them are nonzero, then we can skip
    # past all the words we just saw.
    for idx, word in enumerate(islice(words, VTABLE_OFFSET)):
        if word != 0:
            return False, idx + 1
    # Now this first word after the padding section is special.
    first = next(words, None)
    if first is None:
        # We have 2 zeros followed by the end of our range.
        return False, 2
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
    length = VTABLE_OFFSET + 1 + iterlen(takewhile(lambda word: word != 0, words))
    # Now it's simple: We are valid if the length is long enough, invalid if it's too short.
    return length >= MIN_VTABLE_LENGTH, length

def kernelcache_convert_vtable_to_offsets(vtable):
    """Convert a vtable into a sequence of offsets.

    Arguments:
        vtable: The address of the virtual method table.

    Returns:
        True if the data was successfully converted into offsets.
    """
    possible, length = kernelcache_vtable_length(vtable)
    if not possible:
        _log(0, 'Address {:#x} is not a vtable', vtable)
        return False
    successful = True
    for address in Addresses(vtable, length=length, step=WORD_SIZE):
        if not idc.OpOff(address, 0, 0):
            _log(0, 'Could not change address {:#x} into an offset', address)
            successful = False
    return successful

