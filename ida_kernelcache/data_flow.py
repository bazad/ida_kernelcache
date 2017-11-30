#
# ida_kernelcache/data_flow.py
# Brandon Azad
#
# A module for data flows.
#
"""ida_kernelcache.data_flow

This module contains functions that perform various types of data flow operations on functions or
code ranges. Currently only Arm64 is supported.

While it is possible to implement a very generic data flow framework, allowing custom data flows to
be implemented entirely externally and with little or no knowledge of the underlying architecture,
this module does not take that approach, for reasons of simplicity and efficiency.

"""

import collections

import idc
import idautils
import idaapi

import ida_utilities as idau

_log = idau.make_log(2, __name__)

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

def _create_flow(function, bounds):
    """Create a FlowChart."""
    f, b = None, None
    if function is not None:
        f = idaapi.get_func(function)
        if f is None:
            _log(0, 'Bad func {:#x}', func)
            return None
    if bounds is not None:
        b = (start, end)
    return idaapi.FlowChart(f=f, bounds=b)

def _add_blocks_to_queue(queue, flow, addresses):
    for ea in addresses:
        for bb in flow:
            if bb.startEA <= ea < bb.endEA:
                queue.append(bb)
                break
        else:
            _log(2, 'Address {:#x} not contained in any basic block', ea)

def _pointer_accesses_process_block(start, end, fix, entry_regs, accesses):
    """Process a basic block for _pointer_accesses_data_flow.

    Arm64 only."""
    # NOTE: Some object accesses (to large offsets) are encoded in the following style:
    #   MOV             W8, #0x9210
    #   STR             X0, [X19,X8]
    # We try to catch these by keeping track of local constants within a block.
    RegValue = collections.namedtuple('RegValue', ['type', 'value'])
    DELTA = 0   # Pointer delta from start of target memory region.
    CONST = 1   # Constant value
    def get_reg(reg, type):
        rv = regs.get(reg, None)
        if rv is None or rv.type != type:
            return None
        return rv.value

    # Initialize our registers and create accessor functions.
    regs = { reg: RegValue(DELTA, delta) for reg, delta in entry_regs.items() }

    # For each instruction in the basic block, see if any new register gets assigned.
    for insn in idau.Instructions(start, end):
        # First, if this instruction has a fixed state (i.e., a set mapping of registers to
        # deltas), set that state. This overwrites any previous values, so care must be taken by
        # the caller to ensure that this initialization is correct.
        fixed_regs_and_deltas = fix.get(insn.ea)
        if fixed_regs_and_deltas:
            for reg, delta in fixed_regs_and_deltas.items():
                _log(6, '\t\t{:x}  fix {}={}', insn.ea, reg, delta)
                regs[reg] = RegValue(DELTA, delta)
        # If this is an access instruction, record the access. See comment about auxpref below.
        if not (insn.auxpref & _ARM64_WRITEBACK):
            for op in insn.Operands:
                # We only consider o_displ and o_phrase.
                if op.type == idaapi.o_void:
                    break
                elif op.type not in (idaapi.o_displ, idaapi.o_phrase):
                    continue
                # Get the delta for the base register.
                delta = get_reg(op.reg, DELTA)
                if delta is None:
                    continue
                # Get the instruction access size.
                size = _INSN_OP_DTYP_SZ.get(op.dtyp)
                if size is None:
                    continue
                # Get the offset from the base register (which is additional to the base register's
                # delta).
                op_offset = None
                if op.type == idaapi.o_displ:
                    op_offset = op.addr
                else: # op.type == idaapi.o_phrase
                    op_offset_reg = op.specflag1 & 0xff
                    op_offset = get_reg(op_offset_reg, CONST)
                if op_offset is None:
                    continue
                # Record this access.
                offset = (delta + op_offset) & 0xffffffffffffffff
                _log(5, '\t\t{:x}  access({})  {}, {}', insn.ea, op.reg, offset, size)
                accesses[(offset, size)].add((insn.ea, delta))
        # Update the set of registers pointing to the struct, and the set of known constant
        # registers.
        if (insn.itype == idaapi.ARM_mov
                and insn.Op1.type == idaapi.o_reg
                and insn.Op2.type == idaapi.o_reg
                and insn.Op3.type == idaapi.o_void
                and insn.Op1.dtyp == idaapi.dt_qword
                and insn.Op2.dtyp == idaapi.dt_qword
                and insn.Op2.reg in regs):
            # MOV Xdst, Xsrc
            _log(6, '\t\t{:x}  add {}={}', insn.ea, insn.Op1.reg, regs[insn.Op2.reg].value)
            regs[insn.Op1.reg] = regs[insn.Op2.reg]
        elif (insn.itype == idaapi.ARM_mov
                and insn.Op1.type == idaapi.o_reg
                and insn.Op2.type == idaapi.o_imm
                and insn.Op3.type == idaapi.o_void
                and insn.Op1.dtyp in (idaapi.dt_dword, idaapi.dt_qword)):
            # MOV Xdst, #imm
            _log(7, '\t\t{:x}  const {}={}', insn.ea, insn.Op1.reg, insn.Op2.value)
            regs[insn.Op1.reg] = RegValue(CONST, insn.Op2.value)
        elif (insn.itype == idaapi.ARM_add
                and insn.Op1.type == idaapi.o_reg
                and insn.Op2.type == idaapi.o_reg
                and insn.Op3.type == idaapi.o_imm
                and insn.Op4.type == idaapi.o_void
                and insn.Op1.dtyp == idaapi.dt_qword
                and insn.Op2.dtyp == idaapi.dt_qword
                and insn.Op2.reg in regs):
            # ADD Xdst, Xsrc, #amt
            op2 = regs[insn.Op2.reg]
            _log(6, '\t\t{:x}  add {}={}+{}', insn.ea, insn.Op1.reg, op2.value, insn.Op3.value)
            regs[insn.Op1.reg] = RegValue(op2.type, op2.value + insn.Op3.value)
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
    return { reg: rv.value for reg, rv in regs.items() if rv.type == DELTA }

def _pointer_accesses_data_flow(flow, initialization, accesses):
    """Run the data flow for pointer_accesses."""
    # bb_regs maps each block id to another map from register ids to corresponding struct offsets
    # at the start of the block. We don't consider the case where a register could contain more
    # than one possible offset.
    bb_regs = { bb.id: {} for bb in flow }
    # We'll start by processing those blocks that have an initial value.
    queue = collections.deque()
    _add_blocks_to_queue(queue, flow, initialization)
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
    while queue:
        bb = queue.popleft()
        entry_regs = bb_regs[bb.id]
        _log(3, 'Basic block {}  {:x}-{:x}', bb.id, bb.startEA, bb.endEA)
        _log(4, '\tregs@entry = {}', entry_regs)
        exit_regs = _pointer_accesses_process_block(bb.startEA, bb.endEA, initialization,
                entry_regs, accesses)
        _log(4, '\tregs@exit = {}', exit_regs)
        _log(4, '\tsuccs = {}', [s.id for s in bb.succs()])
        for succ in bb.succs():
            # Add the registers at the end of the block to the registers at the start of its
            # successors' blocks. This is a union since we will track accesses to any register
            # that can point to the struct along any path. As discussed above, any register that
            # already had an offset for a successor is ignored.
            succ_regs = bb_regs[succ.id]
            update = False
            for reg in exit_regs:
                if reg not in succ_regs:
                    update = True
                    succ_regs[reg] = exit_regs[reg]
            # If we added a new register, then we'll process the successor block (again).
            if update:
                queue.append(succ)

def pointer_accesses(function=None, bounds=None, initialization=None, accesses=None):
    """Collect the set of accesses to a pointer register.

    In the flow graph defined by the specified function or code region, find all accesses to the
    memory region pointed to initially by the given register.

    Options:
        function: The address of the function to analyze. Any address within the function may be
            specified. Default is None.
        bounds: A (start, end) tuple containing the start and end addresses of the code region to
            analyze. Default is None.
        initialization: A dictionary of dictionaries, specifying for each instruction start
            address, which registers have which offsets into the memory region of interest. More
            precisely: The keys of initialization are the linear addresses of those instructions
            for which we know that some register points into the memory region of interest. For
            each such instruction, initialization[address] is a map whose keys are the register
            numbers of the registers that point into the memory region. Finally,
            initialization[address][register] is the delta between the start of the memory region
            and where the register points (positive values indicate the register points to a higher
            address than the start). This option must be supplied.
        accesses: If not None, then the given dictionary will be populated with the accesses,
            rather than creating and returning a new dictionary. This dictionary must be of type
            collections.defaultdict(set). Default is None.

    Returns:
        If accesses is None (the default), returns a dictionary mapping each (offset, size) tuple
        to the set of (address, delta) tuples that performed that access.

    Notes:
        Either a function or a code region must be specified. You cannot supply both.

        A common use case is analyzing a function for which we know that one register on entry
        points to a structure. For example, say that the function at address 0x4000 takes as an
        argument in register 10 a pointer 144 bytes in to an unknown structure. The appropriate
        initialization dictionary would be:
            { 0x4000: { 10: 144 } }
    """
    # Create the FlowChart.
    flow = _create_flow(function, bounds)
    if flow is None:
        return None
    # Get the set of (offset, size) accesses by running a data flow.
    create = accesses is None
    if create:
        accesses = collections.defaultdict(set)
    _pointer_accesses_data_flow(flow, initialization, accesses)
    if create:
        accesses = dict(accesses)
        return accesses

