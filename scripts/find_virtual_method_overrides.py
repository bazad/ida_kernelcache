#
# scripts/find_virtual_method_overrides.py
# Brandon Azad
#
# Use ida_kernelcache to find classes that override a virtual method.
#

def kernelcache_find_virtual_method_overrides(classname=None, method=None):
    import idc
    import idaapi
    import ida_kernelcache as kc

    # Define the form to ask for the arguments.
    class MyForm(idaapi.Form):
        def __init__(self):
            swidth = 40
            idaapi.Form.__init__(self, r"""STARTITEM 0
Find virtual method overrides

<#The class#Class :{classname}>
<#The virtual method#Method:{method}>""", {
                'classname': idaapi.Form.StringInput(tp=idaapi.Form.FT_IDENT, swidth=swidth),
                'method':    idaapi.Form.StringInput(tp=idaapi.Form.FT_IDENT, swidth=swidth),
            })
        def OnFormChange(self, fid):
            return 1

    kc.collect_class_info()

    if any(arg is None for arg in (classname, method)):
        f = MyForm()
        f.Compile()
        f.classname.value = classname or ''
        f.method.value    = method    or ''
        ok = f.Execute()
        if ok != 1:
            print 'Cancelled'
            return False
        classname = f.classname.value
        method    = f.method.value
        f.Free()

    if classname not in kc.class_info:
        print 'Not a valid class: {}'.format(classname)
        return False

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

