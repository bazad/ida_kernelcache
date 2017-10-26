#
# ida_kernelcache/kernelcache_ida_segments.py
# Brandon Azad
#
# Rename kernel/kext segments in IDA.
#

from ida_utilities import *

from kplist import kplist_parse

_log = make_log(0, 'kernelcache_ida_segments')

def kernelcache_find_kernel_base():
    """Find the kernel base (the address of the main kernel Mach-O header)."""
    return idaapi.get_fileregion_ea(0)

kernelcache_kernel_base = kernelcache_find_kernel_base()
"""The kernel base address."""

LC_SEGMENT_64 = 0x19

def _macho_segments_and_sections(ea):
    """A generator to iterate through a Mach-O file's segments and sections.

    Each iteration yields a tuple:
        (segname, segstart, segend, [(sectname, sectstart, sectend), ...])
    """
    hdr   = read_struct(ea, 'mach_header_64', asobject=True)
    nlc   = hdr.ncmds
    lc    = int(hdr) + len(hdr)
    lcend = lc + hdr.sizeofcmds
    while lc < lcend and nlc > 0:
        loadcmd = read_struct(lc, 'load_command', asobject=True)
        if loadcmd.cmd == LC_SEGMENT_64:
            segcmd = read_struct(lc, 'segment_command_64', asobject=True)
            segname  = null_terminated(segcmd.segname)
            segstart = segcmd.vmaddr
            segend   = segstart + segcmd.vmsize
            sects    = []
            sc  = int(segcmd) + len(segcmd)
            for i in range(segcmd.nsects):
                sect = read_struct(sc, 'section_64', asobject=True)
                sectname  = null_terminated(sect.sectname)
                sectstart = sect.addr
                sectend   = sectstart + sect.size
                sects.append((sectname, sectstart, sectend))
                sc += len(sect)
            yield (segname, segstart, segend, sects)
        lc  += loadcmd.cmdsize
        nlc -= 1

def _kernelcache_initialize_segments_in_kext(kext, mach_header, skip=[]):
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
        mapped = is_mapped(start)
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

KERNELCACHE_PRELINK_INFO_SECTION = '__PRELINK_INFO.__info'
KERNELCACHE_PRELINK_INFO_DICT    = '_PrelinkInfoDictionary'

kernelcache_prelink_info = dict()
"""The kernelcache __PRELINK_INFO dictionary."""

def kernelcache_initialize_segments():
    """Rename the kernelcache segments in IDA according to the __PRELINK_INFO data.

    Rename the kernelcache segments based on the contents of the __PRELINK_INFO dictionary.
    Segments are renamed according to the scheme '[<kext>:]<segment>.<section>', where '<kext>' is
    the bundle identifier if the segment is part of a kernel extension. The special region
    containing the Mach-O header is renamed '[<kext>:]<segment>.HEADER'.
    """
    global kernelcache_prelink_info
    # TODO: There should be some sort of global initialization for this type of stuff.
    idc.Til2Idb(-1, 'mach_header_64')
    idc.Til2Idb(-1, 'load_command')
    idc.Til2Idb(-1, 'segment_command_64')
    idc.Til2Idb(-1, 'section_64')
    # First rename the kernel segments.
    _log(1, 'Renaming kernel segments')
    kernel_skip = ['__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA', '__PLK_DATA_CONST']
    _kernelcache_initialize_segments_in_kext(None, kernelcache_kernel_base, skip=kernel_skip)
    # Now get the __PRELINK_INFO dictionary.
    prelink_info = idc.SegStart(idc.SegByBase(idc.SegByName(KERNELCACHE_PRELINK_INFO_SECTION)))
    prelink_info = idc.GetString(prelink_info)
    kernelcache_prelink_info.update(kplist_parse(prelink_info))
    # Process each kext identified by the __PRELINK_INFO.
    prelink_info_dicts = kernelcache_prelink_info[KERNELCACHE_PRELINK_INFO_DICT]
    for kext_prelink_info in prelink_info_dicts:
        kext = kext_prelink_info.get('CFBundleIdentifier', None)
        mach_header = kext_prelink_info.get('_PrelinkExecutableLoadAddr', None)
        if kext is not None and mach_header is not None:
            orig_kext = idc.SegName(mach_header).split(':', 1)[0]
            if '.kpi.' not in kext and orig_kext != kext:
                _log(0, 'Renaming kext {} -> {}', orig_kext, kext)
            _log(1, 'Renaming segments in {}', kext)
            _kernelcache_initialize_segments_in_kext(kext, mach_header)

def kernelcache_kext(ea):
    """Return the name of the kext to which the given linear address belongs.

    Only works if segments have been renamed using kernelcache_initialize_segments().
    """
    name = idc.SegName(ea) or ''
    if ':' in name:
        return idc.SegName(ea).split(':', 1)[0]
    return None

