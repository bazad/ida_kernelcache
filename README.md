# ida_kernelcache: An IDA Toolkit for analyzing iOS kernelcaches

<!-- Brandon Azad -->

ida_kernelcache is an IDAPython module for IDA Pro to make working with iOS kernelcaches easier.
The module provides functions to:

* Convert iOS 12's new static tagged pointers into normal kernel pointers.
* Parse the kernel's `__PRELINK_INFO` segment into a Python dictionary.
* Rename the segments in IDA according to the kernel extension name, Mach-O segment, and Mach-O
  section.
* Convert identifiable pointers in some segments into IDA offsets.
* Reconstruct the C++ class hierarchy based on OSMetaClass information.
* Symbolicate C++ virtual method tables (both the vtable itself and its methods).
* Symbolicate offsets in `__got` sections and stub functions in `__stubs` sections.
* Autogenerate IDA structs representing the C++ virtual method tables.
* Autogenerate IDA structs representing the C++ classes in the kernelcache based on observed access
  patterns.

The main processing function is designed to be run before any manual analysis or reverse
engineering. With the default settings, IDA tends to miss a lot of useful information in the
kernelcache. These scripts help IDA along by leveraging the known structure of the kernelcache to
automatically propagate useful information.

In addition to the stock functionality in the module, ida_kernelcache contains several scripts to
make analyzing the iOS kernelcache easier. For example, you can use the scripts to autogenerate C
structs used by a function.

Many of the techniques used in ida_kernelcache were developed for and borrowed directly from
[memctl].

[memctl]: https://github.com/bazad/memctl

## Versions

ida_kernelcache has been tested with IDA Pro 6.95 on kernelcaches for iOS versions 10.1.1, 11.0,
11.2, 11.3.1, and 12.0 beta. Currently only Arm64 kernelcaches from iOS 10 and later are supported.

## Getting started

You need to already have a decompressed kernelcache file loaded into IDA. You can find the URL to
download a particular IPSW from Apple online, and there are a number of public tools (including
memctl) capable of decompressing the kernelcache.

In IDA, select "File" -> "Script file..." from the menu bar, then choose the `ida_kernelcache.py`
script in the main directory. This will load the ida_kernelcache module into the IDAPython
interpreter under the names `ida_kernelcache` and `kc`. In the IDAPython prompt, type
`kc.kernelcache_process()` and hit Enter to start analyzing the kernelcache. This function performs
all the major analyses supported by ida_kernelcache. The function will run for several minutes as
IDA identifies and analyzes new functions.

ida_kernelcache will try not to overwrite user names for addresses. This means that if the
kernelcache has been manually analyzed prior to initialization with `kernelcache_process`, the
results may not be as thorough because user-specified names may block automatic name propagation.
However, there's also no guarantee that ida_kernelcache won't mess up prior analysis, so if you do
decide to run `kernelcache_process` on a kernelcache file which you've already analyzed, make a
backup first.

## The ida_kernelcache module

ida_kernelcache is meant to be loaded via `ida_kernelcache.py`; the submodules in the
`ida_kernelcache` directory are not meant to be loaded directly. However, ida_kernelcache exposes
the functionality of many of these submodules. Here is what each of them does:

* **ida_utilities**:
This module wraps some of IDA's functions to provide an easier-to-use API. Particularly useful are
`is_mapped`, `read_word`, `read_struct`, `force_function`, and `ReadWords`. `is_mapped` checks
whether an address is mapped, and optionally whether it contains a known value. `read_word` reads a
variably-sized word from an address. `read_struct` reads a structure type into a Python dictionary
or Python accessor object, which makes parsing data structures much easier. `force_function` tries
several tricks to convert an address into the start of a function in IDA. `ReadWords` is a
generator to iterate over data words and their addresses in a range.

* **build_struct**:
This internal module contains utilities to automatically populate an IDA struct based on a sequence
of accesses to the struct.

* **class_struct**:
This module provides functions to generate IDA structs representing C++ virtual method tables and
classes. `initialize_vtable_structs` scans the (symbolicated) virtual method tables and creates IDA
structs to hold virtual method pointers. `initialize_class_structs` performs a data flow analysis
on the virtual methods to identify accesses to the fields of each class, then builds IDA structs to
represent the classes. Instructions that appear to reference a field are also converted into
structure offset references. See the module docstring for more details.

* **classes**:
This module defines the `ClassInfo` type that holds information about C++ classes in the
kernelcache and provides the function `collect_class_info` to scan the kernelcache for classes and
populate the global `class_info` dictionary with a map from class names to `ClassInfo` objects. The
`ClassInfo` type records the class name, the OSMetaClass instance, the virtual method table, and
the superclass name for each C++ class. Additionally, each `ClassInfo` object stores references to
the superclass's `ClassInfo` and the `ClassInfo` of all direct subclasses, making it easy to
examine and traverse the class hierarchy. `collect_class_info` also stores the set of all virtual
method tables in the global `vtables` set.

* **data_flow**:
This internal module contains data flow operations used by the rest of ida_kernelcache.

* **kernel**:
This module provides the `base` and `prelink_info` global variables. `base` is the base address of
the kernel image (the start of the kernel's Mach-O header). `prelink_info` is the parsed
`__PRELINK_INFO` dictionary.

* **kplist**:
This module provides the `kplist_parse` function to parse kernel-style plists.

* **metaclass**:
This module provides the function `initialize_metaclass_symbols` which adds a symbol for each
known OSMetaClass instance.

* **offset**:
This module provides the functions `initialize_data_offsets` and `initialize_offset_symbols`. The
former scans through the segments looking for pointers which can be converted into offsets. The
latter symbolicates offsets in the `__got` section of each kext if the target of the offset has a
symbol.

* **segment**:
This module provides the function `initialize_segments` to rename IDA's segments to be more useful.
By default, IDA seems to create the segment names by combining a guess of the bundle identifier
with the Mach-O section describing the region. `initialize_segments` extracts the true bundle
identifier from the `__PRELINK_INFO` dictionary and renames each segment to include the bundle
identifier, Mach-O segment, and Mach-O section. This makes it possible, for example, to distinguish
between `__TEXT.__const` and `__DATA_CONST.__const`. This module also provides the function
`kernelcache_kext` (re-exported at the top level) to determine the kext containing the specified
address (only on the old iOS 11 split-kext kernelcache format).

* **stub**:
Many kexts in the kernelcache contain stub functions in a `__stubs` section that jump to functions
in the kernel proper. Unfortunately, these stubs provide a barrier for propagating cross references
and type information. This module doesn't solve these problems, but it does make looking at stubs a
bit easier by automatically renaming stub functions so that the target function name is visible.
Stubs and their targets are forcibly converted into functions in IDA, which helps make the
functions in IDA line up with the functions in the original source code.

* **tagged_pointers**:
The new iOS 12 merged kernelcache format has the upper 2 bytes of each pointer tagged with an
offset in order to chain the pointers together in a list. This module contains functions for
processing and restoring those tagged pointers.

* **vtable**:
This module provides many useful functions for working with virtual method tables, including
`vtable_length`, `convert_vtable_to_offsets`, `vtable_overrides`, `initialize_vtable_symbols`, and
`initialize_vtable_method_symbols`. `vtable_length` checks whether the specified address could be a
vtable and returns the vtable length. The generator `vtable_overrides` enumerates the virtual
methods in a class which override virtual methods used by the superclass. The function
`initialize_vtable_symbols` adds a symbol for the start of each identified vtable.
`initialize_vtable_method_symbols` iterates through the overridden methods in each vtable and
propagates symbols from the superclass to the subclass. This is possible because most of the base
classes in IOKit are defined in XNU with relatively complete symbol information. Each method
override in the vtable of a subclass must conform to the same interface as the method in the
superclass, which means we can generate a symbol for the override by substituting the subclass's
name for the superclass's name in the virtual method symbol in the superclass. For example, if we
have no name for the virtual method at index 7 in the `AppleKeyStore` class, but we know that the
virtual method at index 7 in its superclass `IOService` is called
`__ZNK9IOService12getMetaClassEv`, then we can infer that index 7 should be called
`__ZNK13AppleKeyStore12getMetaClassEv` in the subclass. This technique can be used to symbolicate
most virtual methods in most classes.

## Other scripts

The `ida_kernelcache_reload.py` script is identical to `ida_kernelcache.py`, except it forces the
`ida_kernelcache` module and all submodules to be reloaded. It is mostly useful for development.

The `scripts` directory contains scripts that use ida_kernelcache to perform some sort of analysis.
These scripts are too specific to be part of the main ida_kernelcache module, but they are useful
when reverse engineering the kernelcache. They include:

* **find_virtual_method_overrides.py**:
A script to find descendants of a class that override a virtual method containing the specified
string. Matching overrides are printed to the console.

* **populate_struct.py**:
Populate fields for a C++ class or C struct by performing data flow analysis starting at the
current address.

* **process_external_methods.py**:
Process an `IOExternalMethod` or `IOExternalMethodDispatch` array into a standard form for use by
fuzzing tools.

## Class reconstruction

If you are using the Hex-Rays decompiler, one of the more interesting features of ida_kernelcache
is the automatic C++ class reconstruction, which will use the OSMetaClass information and data flow
analysis to create IDA structs to represent the classes found in the kernelcache. These
representations can dramatically improve the readability of the pseudocode representation. To learn
more, see the post [Reconstructing C++ classes in the iOS kernelcache using IDA Pro].

[Reconstructing C++ classes in the iOS kernelcache using IDA Pro]: https://bazad.github.io/2018/03/ida-kernelcache-class-reconstruction/

## The new iOS 12 kernelcache format

With iOS 12, Apple introduced a new kernelcache format on some devices. Among the changes, this new
kernelcache's kernel pointers are tagged to link them in a list, presumably to allow iBoot to slide
the kernel without the `_PrelinkLinkKASLROffsets` data in the prelink dictionary. Trying to analyze
a stock kernelcache using this format in IDA is difficult due to the missing cross-references. See
the article [Analyzing the iOS 12 kernelcache's tagged pointers] for details.

[Analyzing the iOS 12 kernelcache's tagged pointers]: https://bazad.github.io/2018/06/ios-12-kernelcache-tagged-pointers/

If you just want to untag the pointers in the kernelcache without performing any additional
processing, run `kc.tagged_pointers.untag_pointers()`.

## A note on generalizing

Some of this functionality likely applies more broadly than just to Apple kernelcaches (for
example, vtable analysis and symbol propagation, or most of the functions in `ida_utilities.py`).
Nonetheless, I've limited the import scope to just the `ida_kernelcache` module because I have not
tested any of this on other types of binaries.

## License

ida_kernelcache is released under the MIT license.

Much of the functionality in ida_kernelcache is borrowed from [memctl], which is also released
under the MIT license. Other sources are noted in the comments in the corresponding files.


---------------------------------------------------------------------------------------------------
Brandon Azad
