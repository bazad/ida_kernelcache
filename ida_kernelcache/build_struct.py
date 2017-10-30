#
# ida_kernelcache/build_struct.py
# Brandon Azad
#
# A module to build an IDA structure automatically from code accesses.
#

import collections

import idc
import idautils
import idaapi

import ida_utilities as idau

_log = idau.make_log(2, __name__)

def _collect_accesses_create_flow(func, start, end):
    """Create the flow for collect_accesses."""
    f, bounds = None, None
    if func is not None:
        f = idaapi.get_func(func)
        if f is None:
            _log(0, 'Bad func {:#x}', func)
            return None
    if start is not None and end is not None:
        bounds = (start, end)
    return idaapi.FlowChart(f=f, bounds=bounds)

_INSN_OP_CHG = [
    idaapi.CF_CHG1,
    idaapi.CF_CHG2,
    idaapi.CF_CHG3,
    idaapi.CF_CHG4,
    idaapi.CF_CHG5,
    idaapi.CF_CHG6,
]

_INSN_OP_DTYP_SZ = {
    idaapi.dt_byte:  1,
    idaapi.dt_word:  2,
    idaapi.dt_dword: 4,
    idaapi.dt_qword: 8,
}

_ARM64_WRITEBACK = 0x20 | 0x80

def _collect_accesses_process_block(start, end, initial_regs, accesses):
    """Process a basic block for _collect_accesses.

    Arm64 only."""
    # For each instruction in the basic block, see if any new register gets assigned.
    regs = initial_regs.copy()
    for insn in idau.Instructions(start, end):
        # First, if this is an accesss instruction, record the access. See comment about auxpref
        # below.
        if not (insn.auxpref & _ARM64_WRITEBACK):
            for op in insn.Operands:
                if op.type == idaapi.o_void:
                    break
                if op.type == idaapi.o_displ:
                    offset = regs.get(op.reg)
                    if offset is not None:
                        size = _INSN_OP_DTYP_SZ.get(op.dtyp)
                        if size is not None:
                            offset = (offset + op.addr) & 0xffffffffffffffff
                            _log(5, '\t\t{:x}  access({})  {}, {}', insn.ea, op.reg, offset, size)
                            accesses[(offset, size)].add(insn.ea)
        # Next, update the set of registers pointing to the struct.
        if (insn.itype == idaapi.ARM_mov
                and insn.Op1.type == idaapi.o_reg
                and insn.Op2.type == idaapi.o_reg
                and insn.Op3.type == idaapi.o_void
                and insn.Op1.dtyp == idaapi.dt_qword
                and insn.Op2.dtyp == idaapi.dt_qword
                and insn.Op2.reg in regs):
            # MOV Xdst, Xsrc
            _log(6, '\t\t{:x}  add {}={}', insn.ea, insn.Op1.reg, regs[insn.Op2.reg])
            regs[insn.Op1.reg] = regs[insn.Op2.reg]
        elif (insn.itype == idaapi.ARM_add
                and insn.Op1.type == idaapi.o_reg
                and insn.Op2.type == idaapi.o_reg
                and insn.Op3.type == idaapi.o_imm
                and insn.Op4.type == idaapi.o_void
                and insn.Op1.dtyp == idaapi.dt_qword
                and insn.Op2.dtyp == idaapi.dt_qword
                and insn.Op2.reg in regs):
            # ADD Xdst, Xsrc, #amt
            _log(6, '\t\t{:x}  add {}={}+{}', insn.ea, insn.Op1.reg, regs[insn.Op2.reg],
                    insn.Op3.value)
            regs[insn.Op1.reg] = regs[insn.Op2.reg] + insn.Op3.value
        elif (insn.itype == idaapi.ARM_bl or insn.itype == idaapi.ARM_blr):
            # A function call (direct or indirect). Any correct compiler should generate code that
            # does not use the temporary registers after a call, but just to be safe, clear all the
            # temporary registers.
            _log(6, '\t\t{:x}  clear temps', insn.ea)
            for r in xrange(0, 19):
                regs.pop(getattr(idautils.procregs, 'X{}'.format(r)).reg, None)
        else:
            # This is an unrecognized instruction. Clear all the registers it modifies.
            feature = insn.get_canon_feature()
            # On Arm64, LDR-type instructions store their writeback behavior in the instructions's
            # auxpref flags. As best I can tell, insn.get_canon_feature()'s CF_CHG* flags indicate
            # whether the operand will change, which is different than the register changing for
            # operands like o_displ that use a register to refer to a memory location. Thus, we
            # actually need to special case auxpref and clear those registers. Fortunately,
            # writeback behavior is only observed in o_displ operands, of which there should only
            # ever be one, so it doesn't matter that auxpref is stored on the instruction and not
            # the operand.
            for op in insn.Operands:
                if op.type == idaapi.o_void:
                    break
                if ((feature & _INSN_OP_CHG[op.n] and op.type == idaapi.o_reg)
                        or (insn.auxpref & _ARM64_WRITEBACK and op.type == idaapi.o_displ)):
                    _log(6, '\t\t{:x}  clear {}', insn.ea, op.reg)
                    regs.pop(op.reg, None)
    return regs

def _collect_accesses_data_flow(flow, reg, accesses):
    """Run the data flow for collect_accesses."""
    # bb_regs maps each block id to another map from register ids to corresponding struct offsets
    # at the start of the block. We don't consider the case where a register could contain more
    # than one possible offset.
    bb_regs = { bb.id: {} for bb in flow }
    bb_regs[flow[0].id][reg] = 0
    # Process each block, propagating its set of registers to its successors. This isn't quite a
    # true data flow: We should run it until there are no more changes, then check the accesses
    # conditions only once it's stabilized. The difference occurs when we've processed block A,
    # which had register R with offset O on entry, then later found a block B that jumps back to
    # block A with register R set to a different offset O'. Ideally we should invalidate the
    # register R at the start of A and undo any accesses it generated. However, in practice the
    # only way this will occur is in a loop, which is usually going to be a valid access to the
    # structure on the first iteration. The case we're worried about is when the A->B->A loop
    # cycles infinitely, giving us the (mistaken) impression that our structure is infinite. We can
    # eliminate this possibility and also get better results if we just decline to update register
    # R with offset O' after processing block A, effectively ignoring loops that increment an
    # offset register.
    queue = collections.deque()
    queue.append(flow[0])
    while queue:
        bb = queue.popleft()
        regs = bb_regs[bb.id]
        _log(3, 'Basic block {}  {:x}-{:x}', bb.id, bb.startEA, bb.endEA)
        _log(4, '\tregs@entry = {}', regs)
        end_regs = _collect_accesses_process_block(bb.startEA, bb.endEA, regs, accesses)
        _log(4, '\tregs@exit = {}', end_regs)
        _log(4, '\tsuccs = {}', [s.id for s in bb.succs()])
        for succ in bb.succs():
            # Add the registers at the end of the block to the registers at the start of its
            # successors' blocks. This is a union since we will track accesses to any register
            # that can point to the struct along any path.
            succ_regs = bb_regs[succ.id]
            update = False
            for reg in end_regs:
                if reg not in succ_regs:
                    update = True
                    succ_regs[reg] = end_regs[reg]
            # If we added a new register, then we'll process the successor block (again).
            if update:
                queue.append(succ)

def collect_accesses(func=None, start=None, end=None, reg=None, accesses=None):
    """Collect the set of accesses to a pointer register.

    In the flow graph defined by the specified function or code region, find all accesses to the
    memory region pointed to initially by the given register.

    Options:
        func: The address of the function to analyze. Any address within the function may be
            specified, but analysis will start at the function entry point. Default is None.
        start: The start address of the code region to analyze. Default is None.
        end: The end address of the code region to analyze. Default is None.
        reg: The register number that initially contains the pointer to the structure. Must be
            supplied.
        accesses: If not None, then the given dictionary will be populated with the accesses,
            rather than creating and returning a new dictionary. This dictionary must be of type
            collections.defaultdict(set). Default is None.

    Returns:
        If accesses is None (the default), returns a dictionary mapping each (offset, size) tuple
        to the set of addresses that performed that access.

    Either a function or a code region must be specified. You cannot supply both.
    """
    # Create the FlowChart.
    flow = _collect_accesses_create_flow(func, start, end)
    if flow is None:
        return None
    # Get the set of (offset, size) accesses by running a data flow.
    create = accesses is None
    if create:
        accesses = collections.defaultdict(set)
    _collect_accesses_data_flow(flow, reg, accesses)
    if create:
        accesses = dict(accesses)
        return accesses

def create_struct_fields(sid=None, name=None, accesses=None, create=True):
    """Create an IDA struct with fields corresponding to the specified access pattern.

    Given a sequence of (offset, size) tuples designating the valid access points to the struct,
    create fields in the struct at the corresponding positions.

    Options:
        sid: The struct id, if the struct already exists.
        name: The name of the struct to update or create.
        accesses: The sequence of (offset, size) tuples representing the valid access points in the
            struct.
        create: If True, then the struct will be created with the specified name if it does not
            already exist. Default is False.

    Either sid or name must be specified.
    """
    # Get the struct id.
    if sid is None:
        # Try to get the existing struct ID; if that fails and we're not allowed to create it,
        # bail.
        sid = idc.GetStrucIdByName(name)
        if sid == idc.BADADDR and not create:
            return False
        # AddStrucEx is documented as returning -1 on failure, but in practice it seems to return
        # BADADDR.
        sid = idc.AddStrucEx(-1, name, 0)
        if sid in (-1, idc.BADADDR):
            _log(0, 'Could not create struct {}', name)
            return False
    else:
        name = idc.GetStrucName(sid)
        if name is None:
            _log(0, 'Invalid struct id {}', sid)
            return False
    # We will name each field purely by its offset.
    def field_name(offset):
        return 'field_{:x}'.format(offset)
    # Now, for each (offset, size) pair, create a struct member. Right now we completely ignore the
    # possibility that some members will overlap (either due to strange assembly or due to union
    # members).
    # TODO: In the future we should address this by either automatically generating sub-unions or
    # choosing the smallest member when permissible (e.g. (0, 8), (0, 2), (4, 4) would create
    # (0, 2), (2, 2), (4, 4)). I'd say the union approach is better except that clang seems to
    # generate large word-sized reads followed by masks when accessing bit flags in a structure,
    # which might make the union approach confusing.
    success = True
    for offset, size in accesses:
        member = field_name(offset)
        ret = idc.AddStrucMember(sid, member, offset, idc.FF_DATA | idau.word_flag(size),
                -1, size)
        if ret != 0:
            success = False
            _log(-1, 'Could not add struct {} member {} offset {} size {}: {}', name, member,
                    offset, size, ret)
    return success

