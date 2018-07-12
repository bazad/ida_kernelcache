#
# ida_kernelcache/segment.py
# Brandon Azad
#
# Functions for interacting with the segments of the kernelcache in IDA. No prior initialization is
# necessary.
#

import idc

import ida_utilities as idau
import kernel

_log = idau.make_log(0, __name__)

idc.Til2Idb(-1, 'mach_header_64')
idc.Til2Idb(-1, 'load_command')
idc.Til2Idb(-1, 'segment_command_64')
idc.Til2Idb(-1, 'section_64')

_LC_SEGMENT_64 = 0x19

def _macho_segments_and_sections(ea):
    """A generator to iterate through a Mach-O file's segments and sections.

    Each iteration yields a tuple:
        (segname, segstart, segend, [(sectname, sectstart, sectend), ...])
    """
    hdr   = idau.read_struct(ea, 'mach_header_64', asobject=True)
    nlc   = hdr.ncmds
    lc    = int(hdr) + len(hdr)
    lcend = lc + hdr.sizeofcmds
    while lc < lcend and nlc > 0:
        loadcmd = idau.read_struct(lc, 'load_command', asobject=True)
        if loadcmd.cmd == _LC_SEGMENT_64:
            segcmd = idau.read_struct(lc, 'segment_command_64', asobject=True)
            segname  = idau.null_terminated(segcmd.segname)
            segstart = segcmd.vmaddr
            segend   = segstart + segcmd.vmsize
            sects    = []
            sc  = int(segcmd) + len(segcmd)
            for i in range(segcmd.nsects):
                sect = idau.read_struct(sc, 'section_64', asobject=True)
                sectname  = idau.null_terminated(sect.sectname)
                sectstart = sect.addr
                sectend   = sectstart + sect.size
                sects.append((sectname, sectstart, sectend))
                sc += len(sect)
            yield (segname, segstart, segend, sects)
        lc  += loadcmd.cmdsize
        nlc -= 1

def _initialize_segments_in_kext(kext, mach_header, skip=[]):
    """Rename the segments in the specified kext."""
    def log_seg(segname, segstart, segend):
        _log(3, '+ segment {: <20} {:x} - {:x}  ({:x})', segname, segstart, segend,
            segend - segstart)
    def log_sect(sectname, sectstart, sectend):
        _log(3, '  section {: <20} {:x} - {:x}  ({:x})', sectname, sectstart, sectend,
                sectend - sectstart)
    def log_gap(gapno, start, end, mapped):
        mapped = 'mapped' if mapped else 'unmapped'
        _log(3, '  gap     {: <20} {:x} - {:x}  ({:x}, {})', gapno, start, end,
            end - start, mapped)
    def process_region(segname, name, start, end):
        assert end >= start
        if segname in skip:
            _log(2, 'Skipping segment {}', segname)
            return
        newname = '{}.{}'.format(segname, name)
        if kext:
            newname = '{}:{}'.format(kext, newname)
        if start == end:
            _log(2, 'Skipping empty region {} at {:x}', newname, start)
            return
        ida_segstart = idc.SegStart(start)
        if ida_segstart == idc.BADADDR:
            _log(0, "IDA doesn't think this is a real segment: {:x} - {:x}", start, end)
            return
        ida_segend = idc.SegEnd(ida_segstart)
        if start != ida_segstart or end != ida_segend:
            _log(0, 'IDA thinks segment {} {:x} - {:x} should be {:x} - {:x}', newname, start, end,
                    ida_segstart, ida_segend)
            return
        _log(2, 'Rename {:x} - {:x}: {} -> {}', start, end, idc.SegName(start), newname)
        idc.SegRename(start, newname)
    def process_gap(segname, gapno, start, end):
        mapped = idau.is_mapped(start)
        log_gap(gapno, start, end, mapped)
        if mapped:
            name = 'HEADER' if start == mach_header else '__gap_' + str(gapno)
            process_region(segname, name, start, end)
    for segname, segstart, segend, sects in _macho_segments_and_sections(mach_header):
        log_seg(segname, segstart, segend)
        lastend = segstart
        gapno   = 0
        for sectname, sectstart, sectend in sects:
            if lastend < sectstart:
                process_gap(segname, gapno, lastend, sectstart)
                gapno += 1
            log_sect(sectname, sectstart, sectend)
            process_region(segname, sectname, sectstart, sectend)
            lastend = sectend
        if lastend < segend:
            process_gap(segname, gapno, lastend, segend)
            gapno += 1

def initialize_segments():
    """Rename the kernelcache segments in IDA according to the __PRELINK_INFO data.

    Rename the kernelcache segments based on the contents of the __PRELINK_INFO dictionary.
    Segments are renamed according to the scheme '[<kext>:]<segment>.<section>', where '<kext>' is
    the bundle identifier if the segment is part of a kernel extension. The special region
    containing the Mach-O header is renamed '[<kext>:]<segment>.HEADER'.
    """
    # First rename the kernel segments.
    _log(1, 'Renaming kernel segments')
    kernel_skip = ['__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA', '__PLK_DATA_CONST']
    _initialize_segments_in_kext(None, kernel.base, skip=kernel_skip)
    # Process each kext identified by the __PRELINK_INFO. In the new kernelcache format 12-merged,
    # the _PrelinkExecutableLoadAddr key is missing for all kexts, so no extra segment renaming
    # takes place.
    prelink_info_dicts = kernel.prelink_info['_PrelinkInfoDictionary']
    for kext_prelink_info in prelink_info_dicts:
        kext = kext_prelink_info.get('CFBundleIdentifier', None)
        mach_header = kext_prelink_info.get('_PrelinkExecutableLoadAddr', None)
        if kext is not None and mach_header is not None:
            orig_kext = idc.SegName(mach_header).split(':', 1)[0]
            if '.kpi.' not in kext and orig_kext != kext:
                _log(0, 'Renaming kext {} -> {}', orig_kext, kext)
            _log(1, 'Renaming segments in {}', kext)
            _initialize_segments_in_kext(kext, mach_header)

_kext_regions = []

def _initialize_kext_regions():
    """Get region information for each kext based on iOS 12's __PRELINK_INFO.__kmod_start.

    NOTE: This only accounts for __TEXT_EXEC, not the other segments."""
    kmod_start = idc.SegByBase(idc.SegByName('__PRELINK_INFO.__kmod_start'))
    if kmod_start == idc.BADADDR:
        return
    for kmod in idau.ReadWords(kmod_start, idc.SegEnd(kmod_start)):
        _log(1, 'Found kmod {:x}', kmod)
        segments = list(_macho_segments_and_sections(kmod))
        if len(segments) != 1:
            _log(0, 'Skipping unrecognized kmod {:x}', kmod)
            continue
        segname, segstart, segend, sects = segments[0]
        if segname != '__TEXT_EXEC' or len(sects) != 1:
            _log(0, 'Skipping unrecognized kmod {:x}', kmod)
            continue
        kmod_name = 'kext.{:x}'.format(kmod)
        _log(1, 'Adding module:  {:x} - {:x}  {}', segstart, segend, kmod_name)
        _kext_regions.append((segstart, segend, kmod_name))

_initialize_kext_regions()

def kernelcache_kext(ea):
    """Return the name of the kext to which the given linear address belongs.

    Only works if segments have been renamed using initialize_segments().

    NOTE: Kexts are not well distinguished on the new iOS 12 merged kernelcache format. Do not rely
    on this function.
    """
    # TODO: This doesn't work on 12-merged kernelcaches!
    name = idc.SegName(ea) or ''
    if ':' in name:
        return idc.SegName(ea).split(':', 1)[0]
    if _kext_regions:
        for start, end, kext in _kext_regions:
            if start <= ea < end:
                return kext
    return None

