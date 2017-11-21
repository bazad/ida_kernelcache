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

    def is_IOExternalMethodDispatch(obj):
        VAR = 0xffffffff
        return (idau.is_mapped(obj.function)
                and (0 <= obj.checkScalarInputCount <= 400 or obj.checkScalarInputCount == VAR)
                and (0 <= obj.checkScalarOutputCount <= 400 or obj.checkScalarOutputCount == VAR))

    def process_IOExternalMethodDispatch(obj):
        return (obj.checkScalarInputCount, obj.checkStructureInputSize,
                obj.checkScalarOutputCount, obj.checkStructureOutputSize)

    TYPE_MAP = {
            'IOExternalMethodDispatch':
                (is_IOExternalMethodDispatch, process_IOExternalMethodDispatch),
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

