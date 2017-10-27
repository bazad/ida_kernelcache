#
# ida_kernelcache/classes.py
# Brandon Azad
#
# This module defines the ClassInfo class, which stores information about a C++ class in the
# kernelcache. It also provides the function collect_class_info() to scan the kernelcache for
# information about C++ classes and populate global variables with the result.
#

import collect_classes

class_info = dict()
"""A global map from class names to ClassInfo objects. See collect_class_info()."""

vtables = set()
"""A global set of all identified virtual method tables in the kernel."""

class ClassInfo(object):
    """Information about a C++ class in a kernelcache."""

    def __init__(self, classname, metaclass, vtable, class_size, superclass_name, meta_superclass):
        self.superclass      = None
        self.subclasses      = set()
        self.classname       = classname
        self.metaclass       = metaclass
        self.vtable          = vtable
        self.class_size      = class_size
        self.superclass_name = superclass_name
        self.meta_superclass = meta_superclass

    def __repr__(self):
        def hex(x):
            if x is None:
                return repr(None)
            return '{:#x}'.format(x)
        return 'ClassInfo({!r}, {}, {}, {}, {!r}, {})'.format(
                self.classname, hex(self.metaclass), hex(self.vtable),
                self.class_size, self.superclass_name, hex(self.meta_superclass))

    def ancestors(self):
        """A generator over all direct or indircet superclasses of this class.

        Ancestors are returned in order from root (most distance) to superclass (closest), and the
        class itself is not returned.
        """
        if self.superclass:
            for ancestor in self.superclass.ancestors():
                yield ancestor
            yield self.superclass

    def descendants(self):
        """A generator over all direct or indircet subclasses of this class.

        Descendants are returned in descending depth-first order: first a subclass will be
        returned, then all of its descendants, before going on to the next subclass of this class.
        """
        for subclass in self.subclasses:
            yield subclass
            for descendant in subclass.descendants():
                yield descendant

def collect_class_info():
    """Collect information about C++ classes defined in a kernelcache.

    This function searches through an iOS kernelcache for information about the C++ classes defined
    in it. It returns a dictionary that maps the C++ class names to a ClassInfo object containing
    metainformation about the class.

    The result of this function call is cached in the class_info global dictionary. If this
    dictionary is nonempty, this function will return its value rather than re-examining the
    kernelcache. To force re-evaluation of this function, clear the class_info dictionary with
    class_info.clear().

    This function also collects the set of all virtual method tables identified in the kernelcache,
    even if the corresponding class could not be identified. This set is stored in the global
    vtables variable.

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
    return class_info
