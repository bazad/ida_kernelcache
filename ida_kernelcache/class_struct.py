#
# ida_kernelcache/class_struct.py
# Brandon Azad
#
# A module to build structs representing the C++ classes in the kernelcache.
#
"""ida_kernelcache.class_struct

This module is responsible for creating the IDA structs representing the various C++ classes found
in the kernelcache, including the structs for the vtables.

Organization:

Each class Class gets four structs: Class, Class::vtable, Class::vmethods and Class::fields.
Class::vmethods is a struct containing the virtual methods for Class that are not present in its
direct superclass. Class::vtable is a struct representing the virtual method table for Class, laid
out as follows:

    struct Class::vtable {
        struct SuperClass1::vmethods SuperClass1;
        struct SuperClass2::vmethods SuperClass2;
        /* ... */
        struct SuperClassN::vmethods SuperClassN;
        struct Class::vmethods       Class;
    };

Here SuperClass1, ..., SuperClassN are the chain of superclasses of Class starting from the root.
(Remember, XNU's C++ does not have multiple inheritance, which means we only have one ancestor
chain. This makes everything much easier!)

There are two styles for how Class is represented: struct slices and unions.

In the struct slices representation, Class::fields is a struct containing those fields in Class not
present in its superclass, shifted to start at offset 0. Class is a struct organized as follows:

    struct Class {
        struct Class::vtable*      vtable;
        struct SuperClass1::fields SuperClass1;
        struct SuperClass2::fields SuperClass2;
        /* ... */
        struct SuperClassN::fields SuperClassN;
        struct Class::fields       Class;
    };

In the unions representation, Class::fields is also a struct containing the fields in Class not
present in its superclass, however this time it is not shifted, so that the fields occur at the
same offset in Class::fields as they do in the original Class class in the kernel. Class is a
union organized as follows:

    union Class {
        struct Class::vtable*      vtable;
        struct SuperClass1::fields SuperClass1;
        struct SuperClass2::fields SuperClass2;
        /* ... */
        struct SuperClassN::fields SuperClassN;
        struct Class::fields       Class;
    };

There are advantages and disadvantages to each representation. The unions representation can be
more flexible if the automated analysis messes up, but so far I have not found a good way to set
the operands of instructions referring to these structures.

TODO: I know it's probably possible with ida_bytes.op_stroff().

We divide the processing into two parts: vtable generation and class generation.

For vtable generation, we initially ignore the problem of setting types for each virtual method
entry in the struct. The primary reason for this is that the method symbols in the kernelcache
don't include return type information, so we can't be sure what the correct return type for each
method is. In the future, another module will be able to populate the vtable structs with proper
type information.

Class generation is more complicated: We first need to collect the set of accesses to each class
struct, then use that information to reconstruct the class fields. Most of the work is done by the
data_flow module, which collects (offset, size) pairs for each virtual method in the class. We
partiton those accesses to their respective classes by class size. (This is not perfect since the
class size reported in the kernel may actually be rounded up. However, for the most part it works
quite well.) Once we know which (offset, size) pairs correspond to which class, we use the
build_struct module to create the appropriate fields in the struct for those accesses.

Rationale:

IDA structs don't have any form of inheritance, which leaves us two options: We can either create a
single struct for each class and then figure out some way of synchronizing changes along the
inheritance chain, or we can rely on some form of struct inclusion to ensure that the members of
each class are defined only in one place, and all subclasses re-use those members by including them
as a substruct.

While creating one struct for each class with all members for the class and its superclasses is
simple and presents most similarly to the original code, synchronizing this representation across
struct changes is complex, and not possible in general. Consider: If a change is made to a member
of the root class in a leaf class, we would need to propagate that change back to the root and then
down to every subclass of the root class. And if along the way we found another change that was
incompatible, there would be no way to automatically discover the right way to resolve the
conflict. Perhaps this solution would work if we could ensure that the propagation code was run
after every single structure change, so that there was no opportunity to develop conflicts, but at
that point the solution is quite complex and requires direct support from IDA.

Instead, I elected for a representation that forces each field of each class to be defined in only
one place. This means the structures look less like the original C++, which is unfortunate and
complicates adding or looking up members by offset from the start of the class. However, I still
believe it's better to avoid the whole synchronization issue.

Even so, there are still several possible ways of representing the classes, each with their own
advantages and disadvantages. I ended up allowing the user to select their desired representation.

For now, we sidestep the problem of setting type information for the function pointers in the
::vmethods structs. The reason for this, as mentioned above, is that the method symbols don't tell
us what the true return type is, so at best we can guess. It is easy enough to scan through the
vtables after the ::vmethods structs have been generated and add type information then, so I'll
avoid over-complicating this module by trying to do that here. Instead, I imagine another module
(called, for example, types) that provides two functions:
    - initialize_method_types: For each C++ method symbol, sets the method type by effectively
      doing SetType(GuessType(method)) for every method with a good symbol.
    - update_vtable_struct_types: For each field in each ::vmethods struct, look at the type of the
      corresponding method, and set the type of the field accordingly.
"""

import collections

import idc
import idautils
import idaapi

import ida_utilities as idau
import build_struct
import classes
import data_flow
import symbol
import vtable

_log = idau.make_log(2, __name__)

#### Vtable generation ############################################################################

def _populate_vmethods_struct(sid, classinfo):
    """Populate the ::vmethods struct."""
    # Loop over the new vtable methods.
    super_nmethods = 0
    if classinfo.superclass:
        super_nmethods = classinfo.superclass.vtable_nmethods
    members = set()
    for index, vmethod in enumerate(vtable.class_vtable_methods(classinfo)):
        # Skip entries in the superclass's vtable.
        if index < super_nmethods:
            continue
        # Get the base name of the method (i.e., for Class::method(args), extract method).
        sym  = idau.get_ea_name(vmethod, user=True)
        base = symbol.method_name(sym)
        if not base:
            base = 'method_{}'.format(index)
        base = symbol.make_ident(base)
        # We'll try to use the base as our method name, but if it already exists, try appending
        # "_1", "_2", etc.
        name   = base
        suffix = 0
        while name in members:
            suffix += 1
            name = '{}_{}'.format(base, suffix)
        members.add(name)
        # Create the member.
        offset = (index - super_nmethods) * idau.WORD_SIZE
        ret = idau.struct_add_ptr(sid, name, offset, type='void *')
        if ret != 0:
            _log(0, 'Could not create {}::vmethods.{}: {}', classinfo.classname, name, ret)
            return False
    return True

def _populate_vtable_struct(sid, classinfo):
    """Populate the ::vtable struct."""
    # For each ancestor from root down to us (inclusive), add our ::vmethods struct.
    for ci in classinfo.ancestors(inclusive=True):
        # Get the offset at which the ::vmethods for ci will be.
        offset = 0
        if ci.superclass:
            offset = ci.superclass.vtable_nmethods * idau.WORD_SIZE
        # The size is ci's vtable length minus the offset.
        vmethods_size = ci.vtable_nmethods * idau.WORD_SIZE - offset
        # If the vmethods_size is 0, skip this entry. Otherwise we get weird
        # "struct->til conversion failed" errors.
        if vmethods_size == 0:
            continue
        # Get the sid for ci's ::vmethods.
        vmethods_sid = idau.struct_open(ci.classname + '::vmethods')
        if vmethods_sid is None:
            _log(0, 'Could not find {}::vmethods', ci.classname)
            return False
        # Add this ::vmethods slice to the ::vtable struct.
        ret = idau.struct_add_struct(sid, ci.classname, offset, vmethods_sid)
        if ret != 0:
            _log(0, 'Could not add {}::vmethods to {}::vtable', ci.classname, classinfo.classname)
            return False
    return True

def _create_vmethods_struct(classinfo):
    """Create the ::vmethods struct for a C++ class."""
    sid = idau.struct_create(classinfo.classname + '::vmethods')
    if sid is None:
        _log(0, 'Could not create {}::vmethods', classinfo.classname)
        return False
    return _populate_vmethods_struct(sid, classinfo)

def _create_vtable_struct(classinfo):
    """Create the ::vtable struct for a C++ class."""
    sid = idau.struct_create(classinfo.classname + '::vtable')
    if sid is None:
        _log(0, 'Could not create {}::vtable', classinfo.classname)
        return False
    return _populate_vtable_struct(sid, classinfo)

def initialize_vtable_structs():
    """Create IDA structs representing the C++ virtual method tables in the kernel."""
    classes.collect_class_info()
    for classinfo in classes.class_info.values():
        _create_vmethods_struct(classinfo)
    for classinfo in classes.class_info.values():
        _create_vtable_struct(classinfo)

#### Classes based on struct slices ###############################################################

def _create_class_structs__slices(classinfo, endmarkers=True):
    """Create the IDA structs for a C++ class."""
    classname = classinfo.classname
    # Open or create the structs.
    sidf = idau.struct_open(classname + '::fields', create=True)
    sid  = idau.struct_open(classname, create=True)
    if sid is None or sidf is None:
        _log(0, 'Could not create class structs for {}', classname)
        return None
    assert all(not idc.IsUnion(s) for s in (sidf, sid))
    # Calculate the size of the ::fields struct.
    if classinfo.superclass:
        # If we have a superclass, our fields start after our superclass's fields end.
        fields_start = classinfo.superclass.class_size
    else:
        # If we don't have a superclass, our fields start after our vtable.
        fields_start = idau.WORD_SIZE
    fields_size = classinfo.class_size - fields_start
    # Add an ::end member to the fields struct if requested.
    if endmarkers:
        ret = idc.AddStrucMember(sidf, classname + '::end', fields_size, idc.FF_UNK, -1, 0)
        if ret not in (0, idc.STRUC_ERROR_MEMBER_NAME, idc.STRUC_ERROR_MEMBER_OFFSET):
            # If that didn't work that's too bad, but continue anyway.
            _log(0, 'Could not create {}::end', classname)
    return sid, sidf, fields_start

def _populate_fields_struct__slices(sid, classinfo, fields_start, accesses):
    """Fill in the members of the ::fields struct based on the accesses."""
    # Sanity check.
    for offset, size in accesses:
        assert fields_start <= offset <= offset + size <= classinfo.class_size
    # For each (offset, size) access, add a member to the struct.
    build_struct.create_struct_fields(sid, accesses=accesses, base=fields_start)

def _populate_wrapper_struct__slices(sid, classinfo):
    """Fill in the members of the wrapper struct."""
    # First add the vtable pointer.
    offset = 0
    vtable_ptr_type = '{}::vtable *'.format(classinfo.classname)
    ret = idau.struct_add_ptr(sid, 'vtable', offset, type=vtable_ptr_type)
    if ret not in (0, idc.STRUC_ERROR_MEMBER_OFFSET):
        _log(0, 'Could not create {}.vtable: {}', classinfo.classname, ret)
        return False
    # Now add all the ::fields structs.
    offset += idau.WORD_SIZE
    for ci in classinfo.ancestors(inclusive=True):
        # Get the sid of the ::fields struct.
        fields_sid = idau.struct_open(ci.classname + '::fields')
        if fields_sid is None:
            _log(0, 'Could not find {}::fields', ci.classname)
            return False
        # If this is a 0-length struct (no fields), skip it.
        size = idc.GetStrucSize(fields_sid)
        if size == 0:
            continue
        # If this is already in the wrapper struct, skip it. This avoids weird
        # STRUC_ERROR_MEMBER_VARLAST errors.
        if idc.GetMemberOffset(sid, ci.classname) != -1:
            continue
        # Add the ::fields struct to the wrapper.
        ret = idau.struct_add_struct(sid, ci.classname, offset, fields_sid)
        if ret != 0:
            _log(0, 'Could not create {}.{}: {}', classinfo.classname, ci.classname, ret)
            return False
        offset += size
    return True

def _populate_class_structs__slices(classinfo, class_accesses, sid, sidf, fields_start):
    """Populate the IDA structs for a C++ class."""
    _populate_fields_struct__slices(sidf, classinfo, fields_start,
            class_accesses[classinfo.classname])
    _populate_wrapper_struct__slices(sid, classinfo)

#### Classes based on unions ######################################################################

def _create_class_structs__unions(classinfo):
    """Create the IDA structs for a C++ class."""
    classname = classinfo.classname
    sidf = idau.struct_open(classname + '::fields', create=True)
    sid  = idau.struct_open(classname, union=True, create=True)
    if sid is None or sidf is None:
        _log(0, 'Could not create class structs for {}', classname)
        return None
    return sid, sidf

def _populate_fields_struct__unions(sid, classinfo, accesses):
    """Fill in the members of the ::fields struct based on the accesses."""
    # Sanity check.
    for offset, size in accesses:
        assert 0 <= offset <= offset + size <= classinfo.class_size
    # For each (offset, size) access, add a member to the struct.
    build_struct.create_struct_fields(sid, accesses=accesses)

def _populate_wrapper_struct__unions(sid, classinfo):
    """Fill in the members of the wrapper struct."""
    # First add the vtable pointer.
    vtable_ptr_type = '{}::vtable *'.format(classinfo.classname)
    ret = idau.struct_add_ptr(sid, 'vtable', -1, type=vtable_ptr_type)
    if ret not in (0, idc.STRUC_ERROR_MEMBER_NAME):
        _log(0, 'Could not create {}.vtable: {}', classinfo.classname, ret)
        return False
    # Now add all the ::fields structs.
    for ci in classinfo.ancestors(inclusive=True):
        # Get the sid of the ::fields struct.
        fields_sid = idau.struct_open(ci.classname + '::fields')
        if fields_sid is None:
            _log(0, 'Could not find {}::fields', ci.classname)
            return False
        # Add the ::fields struct to the wrapper. Ignore STRUC_ERROR_MEMBER_UNIVAR if the ::fields
        # struct has length 0.
        ret = idau.struct_add_struct(sid, ci.classname, -1, fields_sid)
        if ret not in (0, idc.STRUC_ERROR_MEMBER_NAME, idc.STRUC_ERROR_MEMBER_UNIVAR):
            _log(0, 'Could not create {}.{}: {}', classinfo.classname, ci.classname, ret)
            return False
    return True

def _populate_class_structs__unions(classinfo, class_accesses, sid, sidf):
    """Populate the IDA structs for a C++ class."""
    _populate_fields_struct__unions(sidf, classinfo, class_accesses[classinfo.classname])
    _populate_wrapper_struct__unions(sid, classinfo)

#### Class generation #############################################################################

CLASS_SLICES = 'slices'
CLASS_UNIONS = 'unions'

DEFAULT_STYLE = CLASS_SLICES

def initialize_class_structs(style=DEFAULT_STYLE):
    """Create IDA structs representing the C++ classes in the kernel.

    Depends on initialize_vtable_structs.
    """
    # A generator that will yield (virtual_method, classname, X0).
    def virtual_methods():
        for classinfo in classes.class_info.values():
            for _, vmethod, _ in vtable.class_vtable_overrides(classinfo, new=True, methods=True):
                if not idau.is_function_start(vmethod):
                    _log(3, 'Non-function virtual method {:#x} in class {}', vmethod,
                            classinfo.classname)
                    continue
                yield vmethod, classinfo.classname, idautils.procregs.X0.reg
    # Do the standard processing.
    process_functions(virtual_methods(), style=style)

def _collect_all_class_accesses(functions):
    """Collect all accesses to each class by examining the functions.

    Arm64 only.
    """
    all_accesses = collections.defaultdict(lambda: collections.defaultdict(set))
    for function, classname, register in functions:
        data_flow.pointer_accesses(function=function, initialization={ function: { register: 0 } },
                accesses=all_accesses[classname])
    return all_accesses

def _classify_class_accesses(all_accesses, style):
    """Categorize each access by specific class and build a list of operands to convert.

    Arm64 only.
    """
    all_classes    = set()
    class_accesses = collections.defaultdict(collections.Counter)
    class_operands = collections.defaultdict(set)
    # Helper for logging.
    def log_addrs(addresses_and_deltas):
        return ', '.join('{:#x}'.format(ea) for ea, dt in addresses_and_deltas)
    # For each class, look at the accesses associated with that class.
    for classname, accesses in all_accesses.items():
        classinfo = classes.class_info.get(classname)
        if not classinfo:
            _log(-1, 'Skipping non-existent class {}', classname)
            continue
        # Put each (offset, size) pair in the appropriate dictionary. We'll traverse our ancestors
        # from root to leaf, which means the first time this offset/size combination fits in a
        # class, that's the class it goes with.
        ancestors = list(classinfo.ancestors(inclusive=True))
        all_classes.update(ancestors)
        for offset_and_size, addresses_and_deltas in accesses.items():
            offset, size = offset_and_size
            # Accesses to offsets 0-8 are actually not considered part of the ::fields struct since
            # they technically access the vtable. Skip it.
            if offset + size <= idau.WORD_SIZE:
                continue
            for ci in ancestors:
                if offset + size <= ci.class_size:
                    # This is the smallest class that contains all the bytes of the access. If the
                    # start of the access is in a smaller class, then this access spans a class
                    # boundary. There are two possible causes: either there's a bug in the
                    # analyzer, or the superclass's size was rounded up in the initialization
                    # function, meaning this is actually a completely valid access in the current
                    # class. Unfortunately there's no good way to detect this. The CLASS_UNIONS
                    # model can deal with this OK, but the CLASS_SLICES model has problems. Skip
                    # this access if we're not in the CLASS_UNIONS model.
                    superclass_size = idau.WORD_SIZE
                    if ci.superclass:
                        superclass_size = ci.superclass.class_size
                    if offset < superclass_size:
                        _log(-1, 'Class {} has spanning access ({}, {}) from addresses {}',
                                classname, offset, size, log_addrs(addresses_and_deltas))
                        if style != CLASS_UNIONS:
                            break
                    # If the access is unaligned with respect to the size, it's more likely to be
                    # incorrect. Log it, but continue.
                    if offset % size != 0:
                        _log(2, 'Class {} has unaligned access ({}, {}) from addresses {}',
                                classname, offset, size, log_addrs(addresses_and_deltas))
                    # Looks good, add it to the collection.
                    class_accesses[ci.classname][offset_and_size] += len(addresses_and_deltas)
                    class_operands[classname].update(addresses_and_deltas)
                    break
            else:
                # Almost certainly this is caused when the same register is used for two different
                # classes, but the path that gets this class to this access is impossible to satisfy.
                _log(-1, 'Class {} has out-of-bounds access ({}, {}) from addresses {}',
                        classname, offset, size, log_addrs(addresses_and_deltas))
    return all_classes, class_accesses, class_operands

def _convert_operands_to_struct_offsets(access_addresses):
    """Convert the operands that generated struct accesses into struct offsets."""
    for classname, addresses_and_deltas in access_addresses.items():
        sid = idau.struct_open(classname)
        if sid is not None:
            for ea, delta in addresses_and_deltas:
                insn = idautils.DecodeInstruction(ea)
                if insn:
                    for op in insn.Operands:
                        if op.type == idaapi.o_displ:
                            if not idau.insn_op_stroff(insn, op.n, sid, delta):
                                _log(1, 'Could not convert {:#x} to struct offset for class {} '
                                        'delta {}', ea, classname, delta)

def _set_class_style(style):
    """Set the global class style."""
    global _style_was_set, _create_class_structs, _populate_class_structs
    assert style in (CLASS_SLICES, CLASS_UNIONS)
    # Check the current style based on OSObject, a class that should always exist.
    sid = idau.struct_open('OSObject')
    want_union = style == CLASS_UNIONS
    if sid is None:
        # No global style has been set.
        idau.struct_create('OSObject', union=want_union)
    else:
        # A style already exists. Check that the requested style matches.
        is_union = bool(idc.IsUnion(sid))
        if is_union != want_union:
            raise ValueError('Incompatible style {}', style)
    # Set the appropriate functions based on the style.
    if style == CLASS_SLICES:
        _create_class_structs   = _create_class_structs__slices
        _populate_class_structs = _populate_class_structs__slices
    else:
        _create_class_structs   = _create_class_structs__unions
        _populate_class_structs = _populate_class_structs__unions

def process_functions(functions, style=DEFAULT_STYLE):
    """Process additional functions.

    Arguments:
        functions: An iterator returning (function, classname, register) tuples.

    Depends on initialize_class_structs.
    """
    classes.collect_class_info()
    _set_class_style(style)
    # First, for each class, collect all the (offset, size) pairs and their associated (address,
    # delta) pairs.
    all_accesses = _collect_all_class_accesses(functions)
    # Now, classify the accesses. class_accesses is a map from each class name to a counter of how
    # many times we've seen each (offset, size) access pair that falls within the class's own
    # fields. class_operands is a map from each class name to the set of (address, delta) pairs
    # that access that class.
    all_classes, class_accesses, class_operands = _classify_class_accesses(all_accesses, style)
    # Next, for each class, create dummy versions of the class's structs, but don't populate them.
    # We do this first so that we'll have all the types we need available when populating the
    # structs below.
    class_structs = {}
    for classinfo in all_classes:
        data = _create_class_structs(classinfo)
        if data is not None:
            class_structs[classinfo] = data
    # Populate the class's structs using the access tuples.
    for classinfo, data in class_structs.items():
        _populate_class_structs(classinfo, class_accesses, *data)
    # Finally, convert each operand that generated an access into an appropriately typed struct
    # offset reference.
    _convert_operands_to_struct_offsets(class_operands)

#### Vtable type propagation ######################################################################

def _propagate_virtual_method_type_for_method(classinfo, class_vindex, vmethod):
    """Propagate the type of a class's virtual method to the vtable struct."""
    if not idau.is_function_start(vmethod):
        _log(2, 'Not a function start: {:x}', vmethod)
        return False
    vmethod_type = idc.GuessType(vmethod)
    if not vmethod_type:
        _log(2, 'No guessed type: {:x}', vmethod)
        return False
    vmethod_ptr_type = symbol.convert_function_type_to_function_pointer_type(vmethod_type)
    if not vmethod_ptr_type:
        _log(2, 'Could not convert to function pointer type: {:x}', vmethod)
        return False
    vmethods_sid = idau.struct_open(classinfo.classname + '::vmethods')
    vmethod_offset = class_vindex * idau.WORD_SIZE
    vmethod_mid = idc.GetMemberId(vmethods_sid, vmethod_offset)
    if not bool(idc.SetType(vmethod_mid, vmethod_ptr_type)):
        _log(2, 'Could not set vmethod field type: {:x}, {}, {}', vmethod, classinfo.classname,
                class_vindex)
        return False
    return True

def _propagate_virtual_method_types_for_class(classinfo):
    """Propagate the types of a class's virtual methods to the vtable struct."""
    for relative_index, vmethod in enumerate(vtable.class_vtable_methods(classinfo, new=True)):
        _propagate_virtual_method_type_for_method(classinfo, relative_index, vmethod)

def propagate_virtual_method_types_to_vtable_structs():
    """Propagate the types of virtual methods to the corresponding entries in the vtables.

    This helps speed decompilation using Hex-Rays, but is not particularly accurate.

    By default, IDA will guess a type with an empty argument list for any function whose symbol
    includes an unknown struct type, which inhibits proper type inference.
    """
    for classinfo in classes.class_info.values():
        _propagate_virtual_method_types_for_class(classinfo)

