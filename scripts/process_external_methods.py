#
# scripts/process_external_methods.py
# Brandon Azad
#
# Parse a list of IOExternalMethod or IOExternalMethodDispatch structs and print metainformation
# about the selectors in the format:
#   { selector, input_scalars_count, input_structure_size, output_scalars_count, output_structure_size }
#

def kernelcache_process_external_methods(ea=None, struct_type=None, count=None):
    import idc
    import ida_kernelcache as kc
    import ida_kernelcache.ida_utilities as idau

    kIOUCVariableStructureSize = 0xffffffff

    kIOUCTypeMask = 0xf
    kIOUCScalarIScalarO = 0
    kIOUCScalarIStructO = 2
    kIOUCStructIStructO = 3
    kIOUCScalarIStructI = 4

    kIOUCFlags = 0xff

    IOExternalMethod_types = (kIOUCScalarIScalarO, kIOUCScalarIStructO, kIOUCStructIStructO,
            kIOUCScalarIStructI)

    IOExternalMethod_count0_scalar = (kIOUCScalarIScalarO, kIOUCScalarIStructO,
            kIOUCScalarIStructI)

    IOExternalMethod_count1_scalar = (kIOUCScalarIScalarO,)

    def check_scalar(scalar_count):
        return (0 <= scalar_count <= 400)

    def check_structure(structure_size):
        return (0 <= structure_size <= 0x100000 or structure_size == kIOUCVariableStructureSize)

    def is_IOExternalMethodDispatch(obj):
        return (idau.is_mapped(obj.function)
                and check_scalar(obj.checkScalarInputCount)
                and check_structure(obj.checkStructureInputSize)
                and check_scalar(obj.checkScalarOutputCount)
                and check_structure(obj.checkStructureOutputSize))

    def process_IOExternalMethodDispatch(obj):
        return (obj.checkScalarInputCount, obj.checkStructureInputSize,
                obj.checkScalarOutputCount, obj.checkStructureOutputSize)

    def is_IOExternalMethod(obj):
        method_type = obj.flags & kIOUCTypeMask
        check_count0 = check_scalar if method_type in IOExternalMethod_count0_scalar else check_structure
        check_count1 = check_scalar if method_type in IOExternalMethod_count1_scalar else check_structure
        return ((obj.object == 0 or idau.is_mapped(obj.object))
                and (obj.flags & kIOUCFlags == obj.flags)
                and idau.is_mapped(obj.func)
                and method_type in IOExternalMethod_types
                and check_count0(obj.count0)
                and check_count1(obj.count1))

    def process_IOExternalMethod(obj):
        isc, iss, osc, oss = 0, 0, 0, 0
        method_type = obj.flags & kIOUCTypeMask
        if method_type == kIOUCScalarIScalarO:
            isc, osc = obj.count0, obj.count1
        elif method_type == kIOUCScalarIStructO:
            isc, oss = obj.count0, obj.count1
        elif method_type == kIOUCStructIStructO:
            iss, oss = obj.count0, obj.count1
        elif method_type == kIOUCScalarIStructI:
            isc, iss = obj.count0, obj.count1
        else:
            assert False
        return (isc, iss, osc, oss)

    TYPE_MAP = {
            'IOExternalMethodDispatch':
                (is_IOExternalMethodDispatch, process_IOExternalMethodDispatch),
            'IOExternalMethod': (is_IOExternalMethod, process_IOExternalMethod),
    }

    # Get the EA.
    if ea is None:
        ea = idc.ScreenEA()

    # Get the struct_type and the check and process functions.
    if struct_type is None:
        for stype in TYPE_MAP:
            struct_type = stype
            check, process = TYPE_MAP[struct_type]
            obj = idau.read_struct(ea, struct=struct_type, asobject=True)
            if check(obj):
                break
        else:
            print 'Address {:#x} does not look like any known external method struct'.format(ea)
            return False
    else:
        if struct_type not in TYPE_MAP:
            print 'Unknown external method struct type {}'.format(struct_type)
            return False
        check, process = TYPE_MAP[struct_type]
        obj = idau.read_struct(ea, struct=struct_type, asobject=True)
        if not check(obj):
            print 'Address {:#x} does not look like {}'.format(ea, struct_type)

    # Process the external methods.
    selector = 0;
    while (count is None and check(obj)) or (selector < count):
        isc, iss, osc, oss = process(obj)
        print '{{ {:3}, {:5}, {:#10x}, {:5}, {:#10x} }}'.format(selector, isc, iss, osc, oss)
        selector += 1
        ea += len(obj)
        obj = idau.read_struct(ea, struct=struct_type, asobject=True)

    return True

kernelcache_process_external_methods()

