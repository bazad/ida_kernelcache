# ida_kernelcache: An IDA Toolkit for analyzing iOS kernelcaches

<!-- Brandon Azad -->

ida_kernelcache is an IDAPython module for IDA Pro to make working with iOS kernelcaches easier.
The module provides functions to:

* Parse the kernel's `__PRELINK_INFO` segment into a Python dictionary
* Rename the segments in IDA according to the kernel extension name, Mach-O segment, and Mach-O
  section
* Convert identifiable pointers in some segments into IDA offsets
* Reconstruct the C++ class hierarchy based on OSMetaClass information
* Symbolicate C++ virtual method tables (both the vtable itself and its methods)
* Symbolicate offsets in `__got` sections and stub functions in `__stubs` sections

The main processing function is designed to be run before any manual analysis or reverse
engineering. With the default settings, IDA tends to miss a lot of useful information in the
kernelcache. These scripts help IDA along by leveraging the known structure of the kernelcache to
automatically propagate useful information.

Many of the techniques used in ida_kernelcache were developed for and borrowed directly from
[memctl].

[memctl]: https://github.com/bazad/memctl

## Versions

I've tested ida_kernelcache with IDA Pro 6.95 on the iPhone 7 10.1.1 and 11.0 kernelcaches.
Currently only Arm64 kernelcaches from iOS 10 and later are supported.

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

## The module in detail

ida_kernelcache is meant to be loaded via `ida_kernelcache.py`; the submodules in the
`ida_kernelcache` directory provide internal functionality that is not meant to be used directly.
However, here is what each of those scripts does:

* **ida_utilities.py**:
This module wraps some of IDA's functions to provide an easier-to-use API. Particularly useful are
`is_mapped`, `read_word`, `read_struct`, and `ReadWords`. `is_mapped` checks whether an address is
mapped, and optionally whether it contains a known value. `read_word` reads a variably-sized word
from an address. `read_struct` reads a structure type into a Python dictionary or Python accessor
object, which makes parsing data structures much easier. `ReadWords` is a generator to iterate over
data words and their addresses in a range.

* **kplist.py**:
This module implements a kernel-style plist parser in order to parse the `__PRELINK_INFO` segment.

* **kernelcache_ida_segments.py**:
This module provides the function `kernelcache_initialize_segments` to rename IDA's segments to be
more useful. By default, IDA seems to create the segment names by combining a guess of the bundle
identifier with the Mach-O section describing the region. `kernelcache_initialize_segments`
extracts the true bundle identifier from the `__PRELINK_INFO` dictionary and renames each segment
to include the bundle identifier, Mach-O segment, and Mach-O section. In particular, this makes it
possible to distinguish between `__TEXT.__const` and `__DATA_CONST.__const`. This module also
provides the function `kernelcache_kext` to determine the kext containing the specified address.

* **kernelcache_offsets.py**:
This module provides the function `kernelcache_data_offsets` which scans through the segments
looking for pointers which can be converted into offsets.

* **kernelcache_vtable_utilities.py**:
This module provides the functions `kernelcache_vtable_length` and
`kernelcache_convert_vtable_to_offsets`, the latter of which is mostly redundant if
`kernelcache_data_offsets` is used. `kernelcache_vtable_length` checks whether the specified
address could be a vtable and returns the vtable length.

* **kernelcache_class_info.py**:
This module scans for OSMetaClass instances and virtual method tables and uses this information to
construct a class hierarchy. Information about each class is stored in a `ClassInfo` object, which
records the name of the class and superclass, a reference to the superclass's `ClassInfo`, the size
of the class, the address of the OSMetaClass instance, and the address of the class vtable.
The `kernelcache_collect_class_info` function collects all this information, and stores a map from
the class names to `ClassInfo` objects in the global `kernelcache_class_info` dictionary. This
function also stores the set of all virtual method tables (even those that couldn't be matched to a
particular class) in the global `kernelcache_vtables` variable.

* **kernelcache_vtable_methods.py**:
This module provides the generator `kernelcache_vtable_overrides` which enumerates the virtual
methods in a class which override virtual methods used by the superclass.

* **kernelcache_vtable_symbols.py**:
This module provides two useful functions, `kernelcache_add_vtable_symbols` and
`kernelcache_symbolicate_vtable_overrides`. The first adds a symbol for the start of each
identified vtable. The second iterates through the overridden methods in each vtable and propagates
symbols from the superclass to the subclass. This is possible because most of the base classes in
IOKit are defined in XNU with relatively complete symbol information. Each method override in the
vtable of a subclass must conform to the same interface as the method in the superclass, which
means we can generate a symbol for the override by substituting the subclass's name for the
superclass's name in the virtual method symbol in the superclass. For example, if we have no name
for the virtual method at index 7 in the `AppleKeyStore` class, but we know that the virtual method
at index 7 in its superclass `IOService` is called `__ZNK9IOService12getMetaClassEv`, then we can
infer that index 7 should be called `__ZNK13AppleKeyStore12getMetaClassEv` in the subclass. This
technique can be used to symbolicate most virtual methods in most classes.

* **kernelcache_metaclass_symbols.py**:
This module provides the function `kernelcache_add_metaclass_symbols` which adds a symbol for each
known OSMetaClass instance.

* **kernelcache_stubs.py**:
Despite its name, this module actually deals with both stubs and offsets. Many kexts in the
kernelcache contain stub functions in a `__stubs` section that jump to functions in the kernel
proper. Unfortunately, these stubs provide a barrier for propagating cross references and type
information. This module doesn't solve these problems, but it does make looking at stubs a bit
easier by automatically renaming stub functions so that the target function name is visible. Stubs
and their targets are forcibly converted into functions in IDA, which helps make the functions in
IDA line up with the functions in the original source code. Offsets in the `__got` section are
symbolicated similarly.

## A note on generalizing

Some of this functionality likely applies more broadly than just to Apple kernelcaches (for
example, vtable analysis and symbol propagation, or some of the function coercion techniques in
`kernelcache_stubs.py`). Nonetheless, I've prefixed every public function with `kernelcache_`
because I have not tested any of this on other types of binaries.

## License

ida_kernelcache is released under the MIT license.

Much of the functionality in ida_kernelcache is borrowed from [memctl], which is also released
under the MIT license. Other sources are noted in the comments in the corresponding files.

