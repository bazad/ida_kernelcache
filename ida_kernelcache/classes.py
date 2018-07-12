#
# ida_kernelcache/classes.py
# Brandon Azad
#
# This module defines the ClassInfo class, which stores information about a C++ class in the
# kernelcache. It also provides the function collect_class_info() to scan the kernelcache for
# information about C++ classes and populate global variables with the result.
#

import collect_classes
import ida_utilities as idau
import vtable

class_info = {}
"""A global map from class names to ClassInfo objects. See collect_class_info()."""

vtables = {}
"""A global map from the address each virtual method tables in the kernelcache to its length."""

class ClassInfo(object):
    """Information about a C++ class in a kernelcache."""

    def __init__(self, classname, metaclass, vtable, vtable_length, class_size, superclass_name,
            meta_superclass):
        self.superclass      = None
        self.subclasses      = set()
        self.classname       = classname
        self.metaclass       = metaclass
        self.vtable          = vtable
        self.vtable_length   = vtable_length
        self.class_size      = class_size
        self.superclass_name = superclass_name
        self.meta_superclass = meta_superclass

    def __repr__(self):
        def hex(x):
            if x is None:
                return repr(None)
            return '{:#x}'.format(x)
        return 'ClassInfo({!r}, {}, {}, {}, {}, {!r}, {})'.format(
                self.classname, hex(self.metaclass), hex(self.vtable),
                self.vtable_length, self.class_size, self.superclass_name,
                hex(self.meta_superclass))

    @property
    def vtable_methods(self):
        return self.vtable + vtable.VTABLE_OFFSET * idau.WORD_SIZE

    @property
    def vtable_nmethods(self):
        if not self.vtable_length or self.vtable_length < vtable.VTABLE_OFFSET:
            return 0
        return self.vtable_length - vtable.VTABLE_OFFSET

    def ancestors(self, inclusive=False):
        """A generator over all direct or indircet superclasses of this class.

        Ancestors are returned in order from root (most distance) to superclass (closest), and the
        class itself is not returned.

        Options:
            inclusive: If True, then this class is included in the iteration. Default is False.
        """
        if self.superclass:
            for ancestor in self.superclass.ancestors(inclusive=True):
                yield ancestor
        if inclusive:
            yield self

    def descendants(self, inclusive=False):
        """A generator over all direct or indircet subclasses of this class.

        Descendants are returned in descending depth-first order: first a subclass will be
        returned, then all of its descendants, before going on to the next subclass of this class.

        Options:
            inclusive: If True, then this class is included in the iteration. Default is False.
        """
        if inclusive:
            yield self
        for subclass in self.subclasses:
            for descendant in subclass.descendants(inclusive=True):
                yield descendant

def collect_class_info():
    """Collect information about C++ classes defined in a kernelcache.

    This function searches through an iOS kernelcache for information about the C++ classes defined
    in it. It populates the global class_info dictionary, which maps the C++ class names to a
    ClassInfo object containing metainformation about the class.

    To force re-evaluation of the class_info dictionary, call class_info.clear() and then re-run
    this function.

    This function also collects the set of all virtual method tables identified in the kernelcache,
    even if the corresponding class could not be identified. A mapping from each virtual method
    table to its length is stored in the global vtables variable.

    Only Arm64 is supported at this time.

    Only top-level classes are processed. Information about nested classes is not collected.
    """
    global class_info, vtables
    if not class_info:
        vtables.clear()
        result = collect_classes.collect_class_info_internal()
        if result is not None:
            all_class_info, all_vtables = result
            class_info.update(all_class_info)
            vtables.update(all_vtables)
