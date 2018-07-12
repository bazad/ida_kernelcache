#
# ida_kernelcache/collect_classes.py
# Brandon Azad
#
# Collects information about C++ classes in a kernelcache.
#

from collections import defaultdict

import idc
import idautils
import idaapi

import ida_utilities as idau
import classes
import segment
import symbol
import vtable

_log = idau.make_log(1, __name__)

# IDK where IDA defines these.
_MEMOP_PREINDEX  = 0x20
_MEMOP_POSTINDEX = 0x80

_MEMOP_WBINDEX   = _MEMOP_PREINDEX | _MEMOP_POSTINDEX

class _Regs(object):
    """A set of registers for _emulate_arm64."""

    class _Unknown:
        """A wrapper class indicating that the value is unknown."""
        def __add__(self, other):
            return _Regs.Unknown
        def __radd__(self, other):
            return _Regs.Unknown
        def __nonzero__(self):
            return False

    _reg_names = idautils.GetRegisterList()
    Unknown = _Unknown()

    def __init__(self):
        self.clearall()

    def clearall(self):
        self._regs = {}

    def clear(self, reg):
        try:
            del self._regs[self._reg(reg)]
        except KeyError:
            pass

    def _reg(self, reg):
        if isinstance(reg, (int, long)):
            reg = _Regs._reg_names[reg]
        return reg

    def __getitem__(self, reg):
        try:
            return self._regs[self._reg(reg)]
        except:
            return _Regs.Unknown

    def __setitem__(self, reg, value):
        if value is None or value is _Regs.Unknown:
            self.clear(self._reg(reg))
        else:
            self._regs[self._reg(reg)] = value & 0xffffffffffffffff

def _emulate_arm64(start, end, on_BL=None, on_RET=None):
    """A very basic partial Arm64 emulator that does just enough to find OSMetaClass
    information."""
    # Super basic emulation.
    reg = _Regs()
    def load(addr, dtyp):
        if not addr:
            return None
        if dtyp == idaapi.dt_qword:
            size = 8
        elif dtyp == idaapi.dt_dword:
            size = 4
        else:
            return None
        return idau.read_word(addr, size)
    def cleartemps():
        for t in ['X{}'.format(i) for i in range(0, 19)]:
            reg.clear(t)
    for insn in idau.Instructions(start, end):
        _log(11, 'Processing instruction {:#x}', insn.ea)
        mnem = insn.get_canon_mnem()
        if mnem == 'ADRP' or mnem == 'ADR':
            reg[insn.Op1.reg] = insn.Op2.value
        elif mnem == 'ADD' and insn.Op2.type == idc.o_reg and insn.Op3.type == idc.o_imm:
            reg[insn.Op1.reg] = reg[insn.Op2.reg] + insn.Op3.value
        elif mnem == 'NOP':
            pass
        elif mnem == 'MOV' and insn.Op2.type == idc.o_imm:
            reg[insn.Op1.reg] = insn.Op2.value
        elif mnem == 'MOV' and insn.Op2.type == idc.o_reg:
            reg[insn.Op1.reg] = reg[insn.Op2.reg]
        elif mnem == 'RET':
            if on_RET:
                on_RET(reg)
            break
        elif (mnem == 'STP' or mnem == 'LDP') and insn.Op3.type == idc.o_displ:
            if insn.auxpref & _MEMOP_WBINDEX:
                reg[insn.Op3.reg] = reg[insn.Op3.reg] + insn.Op3.addr
            if mnem == 'LDP':
                reg.clear(insn.Op1.reg)
                reg.clear(insn.Op2.reg)
        elif (mnem == 'STR' or mnem == 'LDR') and not insn.auxpref & _MEMOP_WBINDEX:
            if mnem == 'LDR':
                if insn.Op2.type == idc.o_displ:
                    reg[insn.Op1.reg] = load(reg[insn.Op2.reg] + insn.Op2.addr, insn.Op1.dtyp)
                else:
                    reg.clear(insn.Op1.reg)
        elif mnem == 'BL' and insn.Op1.type == idc.o_near:
            if on_BL:
                on_BL(insn.Op1.addr, reg)
            cleartemps()
        else:
            _log(10, 'Unrecognized instruction at address {:#x}', insn.ea)
            reg.clearall()

class _OneToOneMapFactory(object):
    """A factory to extract the largest one-to-one submap."""

    def __init__(self):
        self._as_to_bs = defaultdict(set)
        self._bs_to_as = defaultdict(set)

    def add_link(self, a, b):
        """Add a link between the two objects."""
        self._as_to_bs[a].add(b)
        self._bs_to_as[b].add(a)

    def _make_unique_oneway(self, xs_to_ys, ys_to_xs, bad_x=None):
        """Internal helper to make one direction unique."""
        for x, ys in xs_to_ys.items():
            if len(ys) != 1:
                if bad_x:
                    bad_x(x, ys)
                del xs_to_ys[x]
                for y in ys:
                    del ys_to_xs[y]

    def _build_oneway(self, xs_to_ys):
        """Build a one-way mapping after pruning."""
        x_to_y = dict()
        for x, ys in xs_to_ys.items():
            x_to_y[x] = next(iter(ys))
        return x_to_y

    def build(self, bad_a=None, bad_b=None):
        """Extract the smallest one-to-one submap."""
        as_to_bs = dict(self._as_to_bs)
        bs_to_as = dict(self._bs_to_as)
        self._make_unique_oneway(as_to_bs, bs_to_as, bad_a)
        self._make_unique_oneway(bs_to_as, as_to_bs, bad_b)
        return self._build_oneway(as_to_bs)

def _process_mod_init_func_for_metaclasses(func, found_metaclass):
    """Process a function from the __mod_init_func section for OSMetaClass information."""
    _log(4, 'Processing function {}', idc.GetFunctionName(func))
    def on_BL(addr, reg):
        X0, X1, X3 = reg['X0'], reg['X1'], reg['X3']
        if not (X0 and X1 and X3):
            return
        _log(5, 'Have call to {:#x}({:#x}, {:#x}, ?, {:#x})', addr, X0, X1, X3)
        # OSMetaClass::OSMetaClass(this, className, superclass, classSize)
        if not idc.SegName(X1).endswith("__TEXT.__cstring") or not idc.SegName(X0):
            return
        found_metaclass(X0, idc.GetString(X1), X3, reg['X2'] or None)
    _emulate_arm64(func, idc.FindFuncEnd(func), on_BL=on_BL)

def _process_mod_init_func_section_for_metaclasses(segstart, found_metaclass):
    """Process a __mod_init_func section for OSMetaClass information."""
    segend = idc.SegEnd(segstart)
    for func in idau.ReadWords(segstart, segend):
        _process_mod_init_func_for_metaclasses(func, found_metaclass)

def _should_process_segment(seg, segname):
    """Check if we should process the specified segment."""
    return segname.endswith('__DATA_CONST.__mod_init_func') or \
            segname == '__DATA.__kmod_init'

def _collect_metaclasses():
    """Collect OSMetaClass information from all kexts in the kernelcache."""
    # Collect associations from class names to metaclass instances and vice versa.
    metaclass_to_classname_builder = _OneToOneMapFactory()
    metaclass_to_class_size      = dict()
    metaclass_to_meta_superclass = dict()
    def found_metaclass(metaclass, classname, class_size, meta_superclass):
        metaclass_to_classname_builder.add_link(metaclass, classname)
        metaclass_to_class_size[metaclass]      = class_size
        metaclass_to_meta_superclass[metaclass] = meta_superclass
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not _should_process_segment(ea, segname):
            continue
        _log(2, 'Processing segment {}', segname)
        _process_mod_init_func_section_for_metaclasses(ea, found_metaclass)
    # Filter out any class name (and its associated metaclasses) that has multiple metaclasses.
    # This can happen when multiple kexts define a class but only one gets loaded.
    def bad_classname(classname, metaclasses):
        _log(0, 'Class {} has multiple metaclasses: {}', classname,
                ', '.join(['{:#x}'.format(mc) for mc in metaclasses]))
    # Filter out any metaclass (and its associated class names) that has multiple class names. I
    # have no idea why this would happen.
    def bad_metaclass(metaclass, classnames):
        _log(0, 'Metaclass {:#x} has multiple classes: {}', metaclass,
                ', '.join(classnames))
    # Return the final dictionary of metaclass info.
    metaclass_to_classname = metaclass_to_classname_builder.build(bad_metaclass, bad_classname)
    metaclass_info = dict()
    for metaclass, classname in metaclass_to_classname.items():
        meta_superclass = metaclass_to_meta_superclass[metaclass]
        superclass_name = metaclass_to_classname.get(meta_superclass, None)
        metaclass_info[metaclass] = classes.ClassInfo(classname, metaclass, None, None,
                metaclass_to_class_size[metaclass], superclass_name, meta_superclass)
    return metaclass_info

_VTABLE_GETMETACLASS    = vtable.VTABLE_OFFSET + 7
_MAX_GETMETACLASS_INSNS = 3

def _get_vtable_metaclass(vtable_addr, metaclass_info):
    """Simulate the getMetaClass method of the vtable and check if it returns an OSMetaClass."""
    getMetaClass = idau.read_word(vtable_addr + _VTABLE_GETMETACLASS * idau.WORD_SIZE)
    def on_RET(reg):
        on_RET.ret = reg['X0']
    on_RET.ret = None
    _emulate_arm64(getMetaClass, getMetaClass + idau.WORD_SIZE * _MAX_GETMETACLASS_INSNS,
            on_RET=on_RET)
    if on_RET.ret in metaclass_info:
        return on_RET.ret

def _process_const_section_for_vtables(segstart, metaclass_info, found_vtable):
    """Process a __const section to search for virtual method tables."""
    segend = idc.SegEnd(segstart)
    addr = segstart
    while addr < segend:
        possible, length = vtable.vtable_length(addr, segend, scan=True)
        if possible:
            metaclass = _get_vtable_metaclass(addr, metaclass_info)
            if metaclass:
                _log(4, 'Vtable at address {:#x} has metaclass {:#x}', addr, metaclass)
                found_vtable(metaclass, addr, length)
        addr += length * idau.WORD_SIZE

def _collect_vtables(metaclass_info):
    """Use OSMetaClass information to search for virtual method tables."""
    # Build a mapping from OSMetaClass instances to virtual method tables.
    metaclass_to_vtable_builder = _OneToOneMapFactory()
    vtable_lengths = {}
    # Define a callback for when we find a vtable.
    def found_vtable(metaclass, vtable, length):
        # Add our vtable length.
        vtable_lengths[vtable] = length
        # If our classname has a defined vtable symbol and that symbol's address isn't this vtable,
        # don't add the link.
        classname = metaclass_info[metaclass].classname
        proper_vtable_symbol = symbol.vtable_symbol_for_class(classname)
        proper_vtable_symbol_ea = idau.get_name_ea(proper_vtable_symbol)
        if proper_vtable_symbol_ea not in (idc.BADADDR, vtable):
            return
        # If our vtable has a symbol and it doesn't match the metaclass, skip adding a link.
        vtable_symbol = idau.get_ea_name(vtable, user=True)
        if vtable_symbol:
            vtable_classname = symbol.vtable_symbol_get_class(vtable_symbol)
            if vtable_classname != classname:
                _log(2, 'Declining association between metaclass {:x} ({}) and vtable {:x} ({})',
                        metaclass, classname, vtable, vtable_classname)
                return
        # Add a link if they are in the same kext.
        if segment.kernelcache_kext(metaclass) == segment.kernelcache_kext(vtable):
            metaclass_to_vtable_builder.add_link(metaclass, vtable)
    # Process all the segments with found_vtable().
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('__DATA_CONST.__const'):
            continue
        _log(2, 'Processing segment {}', segname)
        _process_const_section_for_vtables(ea, metaclass_info, found_vtable)
    # If a metaclass has multiple vtables, that's really weird, unless the metaclass is
    # OSMetaClass's metaclass. In that case all OSMetaClass subclasses will have their vtables
    # refer back to OSMetaClass's metaclass.
    def bad_metaclass(metaclass, vtables):
        metaclass_name = metaclass_info[metaclass].classname
        if metaclass_name != 'OSMetaClass':
            vtinfo = ['{:#x}'.format(vt) for vt in vtables]
            _log(0, 'Metaclass {:#x} ({}) has multiple vtables: {}', metaclass,
                    metaclass_name, ', '.join(vtinfo))
    # If a vtable has multiple metaclasses, that's really weird.
    def bad_vtable(vtable, metaclasses):
        mcinfo = ['{:#x} ({})'.format(mc, metaclass_info[mc].classname) for mc in metaclasses]
        _log(0, 'Vtable {:#x} has multiple metaclasses: {}', vtable, ', '.join(mcinfo))
    metaclass_to_vtable = metaclass_to_vtable_builder.build(bad_metaclass, bad_vtable)
    # The resulting mapping may have fewer metaclasses than metaclass_info.
    class_info = dict()
    for metaclass, classinfo in metaclass_info.items():
        # Add the vtable and its length, which we didn't have earlier. If the current class doesn't
        # have a vtable, take it from the superclass (recursing if necessary).
        metaclass_with_vtable = metaclass
        while metaclass_with_vtable:
            vtable = metaclass_to_vtable.get(metaclass_with_vtable, None)
            if vtable:
                classinfo.vtable        = vtable
                classinfo.vtable_length = vtable_lengths[vtable]
                break
            classinfo_with_vtable = metaclass_info.get(metaclass_with_vtable, None)
            if not classinfo_with_vtable:
                break
            metaclass_with_vtable = classinfo_with_vtable.meta_superclass
        # Set the superclass field and add the current classinfo to the superclass's children. This
        # is safe since this is the last filtering operation.
        superclass = metaclass_info.get(classinfo.meta_superclass, None)
        if superclass:
            classinfo.superclass = metaclass_info[classinfo.meta_superclass]
            classinfo.superclass.subclasses.add(classinfo)
        # Add the classinfo to the final dictionary.
        class_info[classinfo.classname] = classinfo
    return class_info, vtable_lengths

def _check_filetype(filetype):
    """Checks that the filetype is compatible before trying to process it."""
    return 'Mach-O' in filetype and 'ARM64' in filetype

def collect_class_info_internal():
    """Collect information about C++ classes defined in a kernelcache.

    Arm64 only.
    """
    filetype = idaapi.get_file_type_name()
    if not _check_filetype(filetype):
        _log(-1, 'Bad file type "{}"', filetype)
        return None
    _log(1, 'Collecting information about OSMetaClass instances')
    metaclass_info = _collect_metaclasses()
    if not metaclass_info:
        _log(-1, 'Could not collect OSMetaClass instances')
        return None
    _log(1, 'Searching for virtual method tables')
    class_info, all_vtables = _collect_vtables(metaclass_info)
    if not class_info:
        _log(-1, 'Could not collect virtual method tables')
        return None
    _log(1, 'Done')
    return class_info, all_vtables

