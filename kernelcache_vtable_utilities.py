#
# kernelcache_vtable_utilities.py
# Brandon Azad
#

from idc import OpOff, SegEnd

from ida_utilities import WORD_SIZE, Addresses, ReadWords, iterlen

from itertools import islice, takewhile

VTABLE_OFFSET      =  2
MIN_VTABLE_METHODS = 12
MIN_VTABLE_LENGTH  = VTABLE_OFFSET + MIN_VTABLE_METHODS

_kernelcache_vtable_utilities__log_level = 0

def _log(level, fmt, *args):
    if level <= _kernelcache_vtable_utilities__log_level:
        print 'kernelcache_vtable_utilities: ' + fmt.format(*args)

def kernelcache_vtable_length(ea, end=None, scan=False):
    """Checks whether the effective address could correspond to a virtual method table.

    If the given virtual address could be a vtable, it returns True and the length of the vtable in
    words (including the initial zero entries). If the given virtual address is definitely not a
    vtable, then it returns False and the number of words that can be skipped in searching for the
    next vtable. As a slight optimization when using this function to scan for vtables, setting
    scan to True will cause this function to look ahead in some cases to increase the amount of
    data that can be skipped, reducing duplication of effort between subsequent calls.
    """
    if end is None:
        end = SegEnd(ea)
    words = ReadWords(ea, end)
    # Iterate through the first VTABLE_OFFSET words. If any of them are nonzero, then we can skip
    # past all the words we just saw.
    for idx, word in enumerate(islice(words, VTABLE_OFFSET)):
        if word != 0:
            return False, idx + 1
    # Now this first word after the padding section is special.
    if next(words, None) is None:
        # We have VTABLE_OFFSET + 1 zero entries.
        zeros = VTABLE_OFFSET + 1
        if scan:
            # To avoid re-reading the data we just read in the case of a zero-filled section, let's
            # look ahead a bit until we find the first non-zero value.
            for word in words:
                if word != 0:
                    break
                zeros += 1
            else:
                # We found no nonzero words before the end.
                return False, zeros
        # We can skip all but the last VTABLE_OFFSET zeros.
        return False, zeros - VTABLE_OFFSET
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
        if not OpOff(address, 0, 0):
            _log(0, 'Could not change address {:#x} into an offset', address)
            successful = False
    return successful

