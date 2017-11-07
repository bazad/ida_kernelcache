#
# scripts/populate_struct.py
# Brandon Azad
#
# Populate a struct using data flow analysis.
#

def kernelcache_populate_struct(struct=None, address=None, register=None, delta=None):
    import idc
    import idautils
    import idaapi
    import ida_kernelcache as kc
    import ida_kernelcache.ida_utilities as idau

    # Define the form to ask for the arguments.
    class MyForm(idaapi.Form):
        def __init__(self):
            swidth = 40
            idaapi.Form.__init__(self, r"""STARTITEM 0
Automatically populate struct fields

<#The name of the structure#Structure:{structure}>
<#The address of the instruction at which the register points to the structure#Address  :{address}>
<#The register containing the pointer to the structure#Register :{register}>
<#The offset of the pointer from the start of the structure#Delta    :{delta}>""", {
                'structure': idaapi.Form.StringInput( tp=idaapi.Form.FT_IDENT, swidth=swidth),
                'address':   idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,  swidth=swidth, width=1000),
                'register':  idaapi.Form.StringInput( tp=idaapi.Form.FT_IDENT, swidth=swidth),
                'delta':     idaapi.Form.NumericInput(tp=idaapi.Form.FT_INT64, swidth=swidth),
            })
        def OnFormChange(self, fid):
            return 1

    # If any argument is unspecified, get it using the form.
    if any(arg is None for arg in (struct, address, register, delta)):
        f = MyForm()
        f.Compile()
        f.structure.value = struct or 'struc'
        f.address.value   = address or idc.ScreenEA()
        f.register.value  = register or 'X0'
        f.delta.value     = delta or 0
        ok = f.Execute()
        if ok != 1:
            print 'Cancelled'
            return False
        struct   = f.structure.value
        address  = f.address.value
        register = f.register.value
        delta    = f.delta.value
        f.Free()

    # Open the structure.
    sid = idau.struct_open(struct, create=True)
    if sid is None:
        print 'Could not open struct {}'.format(struct)
        return False

    # Check that the address is in a function.
    if not idaapi.get_func(address):
        print 'Address {:#x} is not a function'.format(address)
        return False

    # Get the register id.
    register_id = None
    if type(register) is str:
        register_id = idaapi.str2reg(register)
    elif type(register) is int:
        register_id = register
        register    = idaapi.get_reg_name(register_id, 8)
    if register_id is None or register_id < 0:
        print 'Invalid register {}'.format(register)
        return False

    # Validate delta.
    if delta < 0 or delta > 0x1000000:
        print 'Invalid delta {}'.format(delta)
        return False

    print 'struct = {}, address = {:#x}, register = {}, delta = {:#x}'.format(struct, address,
            register, delta)

    # Run the data flow to collect the accesses and then add those fields to the struct.
    accesses = kc.data_flow.pointer_accesses(function=address,
            initialization={ address: { register_id: delta } })
    kc.build_struct.create_struct_fields(sid, accesses=accesses)

    # Set the offsets to stroff.
    for addresses_and_deltas in accesses.values():
        for ea, delta in addresses_and_deltas:
            insn = idautils.DecodeInstruction(ea)
            if insn:
                for op in insn.Operands:
                    if op.type == idaapi.o_displ:
                        idc.OpStroffEx(ea, op.n, sid, delta)

    # All done! :)
    print 'Done'
    return True

kernelcache_populate_struct()

