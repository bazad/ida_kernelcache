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

Class::fields is a struct containing those fields in Class not present in its superclass. Class is
a struct organized as follows:

    struct Class {
        struct Class::vtable*      vtable;
        struct SuperClass1::fields SuperClass1;
        struct SuperClass2::fields SuperClass2;
        /* ... */
        struct SuperClassN::fields SuperClassN;
        struct Class::fields       Class;
    };

Here SuperClass1, ..., SuperClassN are the chain of superclasses of Class starting from the root.
(Remember, XNU's C++ does not have multiple inheritance, which means we only have one ancestor
chain. This makes everything much easier!)

We divide the processing into two parts: vtable generation and class generation.

For vtable generation, we initially ignore the problem of setting types for each virtual method
entry in the struct. The primary reason for this is that the method symbols in the kernelcache
don't include return type information, so we can't be sure what the correct return type for each
method is. In the future, another module will be able to populate the vtable structs with proper
type information.

Class generation is more complicated: We first need to collect the set of accesses to each class
struct, then use that information to reconstruct the class fields.

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
import vtable

_log = idau.make_log(2, __name__)

def _method_name(symbol):
    """Get the name of the C++ method from its symbol."""
    # TODO: Extracting the method name from a C++ symbol should probably be done in a symbol
    # module.
    try:
        demangled  = idc.Demangle(symbol, idc.GetLongPrm(idc.INF_SHORT_DN))
        func       = demangled.split('::', 1)[1]
        base       = func.split('(', 1)[0]
        return base or None
    except:
        return None

def make_ident(name):
    """Convert a name into a valid identifier, substituting any invalid characters."""
    ident = ''
    for c in name:
        if idaapi.is_ident_char(c):
            ident += c
        else:
            ident += '_'
    return ident

def _populate_vmethods_struct(sid, classinfo):
    """Populate the ::vmethods struct."""
    # Loop over the new vtable methods.
    super_nmethods = 0
    if classinfo.superclass:
        super_nmethods = classinfo.superclass.vtable_nmethods
    ptr_flag = idc.FF_DATA | idau.word_flag(idau.WORD_SIZE) | idaapi.offflag()
    members = set()
    for index, vmethod in enumerate(vtable.class_vtable_methods(classinfo)):
        # Skip entries in the superclass's vtable.
        if index < super_nmethods:
            continue
        # Get the base name of the method (i.e., for Class::method(args), extract method).
        symbol = idau.get_ea_name(vmethod, user=True)
        base   = _method_name(symbol)
        if base:
            base = make_ident(base)
        else:
            base = 'method_{}'.format(index)
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
        ret = idc.AddStrucMember(sid, name, offset, ptr_flag, 0, idau.WORD_SIZE)
        if ret != 0:
            _log(0, 'Could not create {}::vmethods.{}: {}', classinfo.classname, name, ret)
            return False
        # Set the type of the member to "void *", but don't worry if that fails.
        mid = idc.GetMemberId(sid, offset)
        if not idc.SetType(mid, 'void *'):
            _log(1, 'Could not set type of {}::vmethods.{}', classinfo.classname, name)
    return True

def _populate_vtable_struct(sid, classinfo):
    """Populate the ::vtable struct."""
    # For each ancestor from root down to us (inclusive), add our ::vmethods struct.
    vmethods_flag = idc.FF_DATA | idc.FF_STRU
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
        vmethods_sid = idc.GetStrucIdByName(ci.classname + '::vmethods')
        if vmethods_sid == idc.BADADDR:
            _log(0, 'Could not find {}::vmethods', ci.classname)
            return False
        # Add this ::vmethods slice to the ::vtable struct.
        ret = idc.AddStrucMember(sid, ci.classname, offset, vmethods_flag, vmethods_sid,
                vmethods_size)
        if ret != 0:
            _log(0, 'Could not add {}::vmethods to {}:vtable', ci.classname, classinfo.classname)
            return False
    return True

def _create_vmethods_struct(classinfo):
    """Create the ::vmethods struct for a C++ class."""
    sid = idc.AddStrucEx(-1, classinfo.classname + '::vmethods', 0)
    if sid in (-1, idc.BADADDR):
        _log(0, 'Could not create {}::vmethods', classinfo.classname)
        return False
    return _populate_vmethods_struct(sid, classinfo)

def _create_vtable_struct(classinfo):
    """Create the ::vtable struct for a C++ class."""
    sid = idc.AddStrucEx(-1, classinfo.classname + '::vtable', 0)
    if sid in (-1, idc.BADADDR):
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

def _collect_class_accesses(classinfo, class_accesses):
    """Collect all accesses to the class or any of its superclasses by examining its vtable.

    Arm64 only.
    """
    # First collect all the accesses in the vtable overrides. (Any non-overridden virtual methods
    # will be processed in the originating class.)
    accesses = collections.defaultdict(set)
    for _, vmethod, _ in vtable.class_vtable_overrides(classinfo, new=True, methods=True):
        if not idau.is_function_start(vmethod):
            _log(0, 'Non-function virtual method {:#x} in class {}', vmethod, classinfo.classname)
            continue
        build_struct.collect_accesses(func=vmethod, reg=idautils.procregs.X0.reg,
                accesses=accesses)
    # Now put each (offset, size) pair in the appropriate dictionary. We'll traverse our ancestors
    # from root to leaf, which means the first time this offset/size combination fits in a class,
    # that's the class it goes with.
    def log_addrs(addresses):
        return ', '.join('{:#x}'.format(addr) for addr in addresses)
    classes = list(classinfo.ancestors(inclusive=True))
    for offset_and_size, addresses in accesses.items():
        offset, size = offset_and_size
        # Accesses to offsets 0-8 are actually not considered part of the ::fields struct since
        # they technically access the vtable. Skip it.
        if offset + size <= idau.WORD_SIZE:
            continue
        for ci in classes:
            if offset + size <= ci.class_size:
                # This is the smallest class that contains all the bytes of the access. If the
                # start of the access is in a smaller class, then this access spans a class
                # boundary. There are two possible causes: either there's a bug in the analyzer, or
                # the superclass's size was rounded up in the initialization function, meaning this
                # is actually a completely valid access in the current class. Unfortunately there's
                # no good way to detect this.
                # TODO: This type of issue would also be very hard to correct manually, since you'd
                # need to change the sizes of several structs.
                superclass_size = idau.WORD_SIZE
                if ci.superclass:
                    superclass_size = ci.superclass.class_size
                if offset < superclass_size:
                    _log(-1, 'Class {} has spanning access ({}, {}) from addresses {}',
                            classinfo.classname, offset, size, log_addrs(addresses))
                    break
                # If the access is unaligned with respect to the size, it's more likely to be
                # incorrect. Log it, but continue.
                if offset % size != 0:
                    _log(2, 'Class {} has unaligned access ({}, {}) from addresses {}',
                            classinfo.classname, offset, size, log_addrs(addresses))
                class_accesses[ci.classname][offset_and_size].update(addresses)
                break
        else:
            _log(-1, 'Class {} has out-of-bounds access ({}, {}) from addresses {}',
                    classinfo.classname, offset, size, log_addrs(addresses))

def _create_class_structs(classinfo):
    """Create the IDA structs for a C++ class."""
    classname = classinfo.classname
    # Create the structs.
    sidf = idc.AddStrucEx(-1, classname + '::fields', 0)
    sid  = idc.AddStrucEx(-1, classname, 0)
    if any(s in (-1, idc.BADADDR) for s in (sidf, sid)):
        _log(0, 'Could not create class structs for {}', classname)
        return None
    # Calculate the size of the ::fields struct.
    if classinfo.superclass:
        # If we have a superclass, our fields start after our superclass's fields end.
        fields_start = classinfo.superclass.class_size
    else:
        # If we don't have a superclass, our fields start after our vtable.
        fields_start = idau.WORD_SIZE
    fields_size = classinfo.class_size - fields_start
    # Add a ::end member to the fields struct.
    ret = idc.AddStrucMember(sidf, classname + '::end', fields_size, idc.FF_UNK, -1, 0)
    if ret != 0:
        # If that didn't work that's too bad, but continue anyway.
        _log(0, 'Could not create {}::end', classname)
    return sid, sidf, fields_start

def _populate_fields_struct(sid, classinfo, fields_start, accesses):
    """Fill in the members of the ::fields struct based on the accesses."""
    classname = classinfo.classname
    # For each (offset, size) access, add a member to the struct.
    for offset, size in accesses:
        assert fields_start <= offset <= offset + size <= classinfo.class_size
        # Create a field for the access.
        name = 'field_{:x}'.format(offset)
        relative_offset = offset - fields_start
        _log(3, 'Creating {}::fields.{} offset {} size {}', classname, name, offset,
                size)
        ret = idc.AddStrucMember(sid, name, relative_offset, idc.FF_DATA | idau.word_flag(size),
                -1, size)
        if ret != 0:
            if ret == idc.STRUC_ERROR_MEMBER_OFFSET:
                _log(1, 'Could not create {}::fields.{} size {}', classname, name, size)
            else:
                _log(1, 'Could not create {}::fields.{} size {}: {}', classname, name, size, ret)

def _populate_wrapper_struct(sid, classinfo):
    """Fill in the members of the wrapper struct."""
    # First add the vtable pointer.
    offset = 0
    ptr_flag = idc.FF_DATA | idau.word_flag(idau.WORD_SIZE) | idaapi.offflag()
    ret = idc.AddStrucMember(sid, 'vtable', offset, ptr_flag, 0, idau.WORD_SIZE)
    if ret != 0:
        _log(0, 'Could not create {}.vtable: {}', classinfo.classname, ret)
        return False
    # Set the type of the vtable pointer to "::vtable *", but don't worry if that fails.
    mid = idc.GetMemberId(sid, offset)
    if not idc.SetType(mid, '{}::vtable *'.format(classinfo.classname)):
        _log(1, 'Could not set type of {}.vtable', classinfo.classname)
    # Now add all the ::fields structs.
    offset += idau.WORD_SIZE
    fields_flag = idc.FF_DATA | idc.FF_STRU
    for ci in classinfo.ancestors(inclusive=True):
        # Get the sid of the ::fields struct.
        sidm = idc.GetStrucIdByName(ci.classname + '::fields')
        if sidm == idc.BADADDR:
            _log(0, 'Could not find {}::fields', ci.classname)
            return False
        # If this is a 0-length struct (no fields), skip it.
        size = idc.GetStrucSize(sidm)
        if size == 0:
            continue
        # Add the ::fields struct to the wrapper.
        ret = idc.AddStrucMember(sid, ci.classname, offset, fields_flag, sidm, size)
        if ret != 0:
            _log(0, 'Could not create {}.{}: {}', classinfo.classname, ci.classname, ret)
            return False
        offset += size
    return True

def _populate_class_structs(classinfo, class_accesses, sid, sidf, fields_start):
    """Populate the IDA structs for a C++ class."""
    _populate_fields_struct(sidf, classinfo, fields_start, class_accesses[classinfo.classname])
    _populate_wrapper_struct(sid, classinfo)

def initialize_class_structs():
    """Create IDA structs representing the C++ classes in the kernel.

    Depends on initialize_vtable_structs.
    """
    classes.collect_class_info()
    # First, for each class, collect all the unique (offset, size) access tuples. class_accesses is
    # a map from each class name to a dictionary of (offset, size) tuples and the set of addresses
    # that perform that access.
    class_accesses = { cn: collections.defaultdict(set) for cn in classes.class_info }
    for classinfo in classes.class_info.values():
        _collect_class_accesses(classinfo, class_accesses)
    # Next, for each class, create dummy versions of the class's structs, but don't populate them.
    created = {}
    for classinfo in classes.class_info.values():
        data = _create_class_structs(classinfo)
        if data is not None:
            created[classinfo] = data
    # Populate the class's structs using the access tuples.
    for classinfo, data in created.items():
        _populate_class_structs(classinfo, class_accesses, *data)
    # Finally, convert each access to a struct offset reference.
    # TODO

