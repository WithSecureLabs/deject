"""!
@brief Search the memory dump for InvokeBof and try and find the EXE or DLL invoked.
@details InvokeBof is used in (https://github.com/CCob/BOF.NET) and could indicate
if additional tooling has been invoked from the C2.
However, if a BOF is expected and this does not pick it up, manual analysis is needed.
"""
from deject.plugins import Deject


@Deject.plugin
def list_bofs():
    """check for InvokeBof in the memory dump"""
    sections = Deject.r2_handler.cmd(r"izzz | grep \"InvokeBof\" -C 5 | grep \"\.exe$\"")
    sections += Deject.r2_handler.cmd(r"izzz | grep \"InvokeBof\" -C 5 | grep \"\.dll$\"")
    if sections is None: 
        print("InvokeBof not found in Dump. Potentially BOF free!")
        return
    rows = []
    # check for duplicates
    for d in sections.split("\n"):
        if d != "":
            exe = d.split(" ")[9]
            section = d.split(" ")[7]
            rows.append([exe, section])

    res = {"header":["Exe Name","Memory Section"], "rows": rows}

    return res

def help():
    print("""
InvokeBof Plugin
SYNOPSIS <filename>
This plugin will search a memory dump for 'InvokeBof' and try and find an EXE or DLL around the
location, to see what could have been loaded and run.
This plugin takes no additional arguments.
""")