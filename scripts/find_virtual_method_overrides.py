#
# scripts/find_virtual_method_overrides.py
# Brandon Azad
#
# Use ida_kernelcache to find classes that override a virtual method.
#

def kernelcache_find_virtual_method_overrides(classname=None, method=None):
    import idc
    import ida_kernelcache as kc

    kc.collect_class_info()

    if not classname:
        classname = idc.AskStr('IOUserClient', 'Enter class name')
    if classname not in kc.class_info:
        print 'Not a valid class: {}'.format(classname)
        return False

    if not method:
        method = idc.AskStr('externalMethod', 'Enter method name')

    print 'Subclasses of {} that override {}:'.format(classname, method)
    baseinfo = kc.class_info[classname]
    found = False
    for classinfo in baseinfo.descendants():
        for _, override, _ in kc.vtable.class_vtable_overrides(classinfo, superinfo=baseinfo,
                methods=True):
            name = idc.NameEx(idc.BADADDR, override)
            demangled = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
            name = demangled if demangled else name
            if method in name:
                print '{:#x}  {}'.format(override, classinfo.classname)
                found = True
    if not found:
        print 'No subclass of {} overrides {}'.format(classname, method)
    return found

kernelcache_find_virtual_method_overrides()

