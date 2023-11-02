"""!
@brief List executable files in a memory dump.
@details More than one executable in a memory dump is suspicious
and could indicate injection.
"""
from deject.plugins import Deject
import ssdeep
import binascii


def extract(sections):
    exes = []
    for s in sections:
        if s["name"][-4:] == ".exe":
            exes.append(s)
    return exes


@Deject.plugin
def list_exes():
    """List the executables in the memory dump, having more than 1 is a good anomaly indicator."""

    sections = Deject.r2_handler.cmdj("iSj")
    if sections is None: 
        print("No exe(s) detected in the dump, this might be a bug!")
        return
    exes = extract(sections)
    rows = []
    if len(exes) > 1:
        print("More than 1 exe found!")
    for exe in exes:
        content = Deject.r2_handler.cmd("p8 {} @ {}".format(exe['size'], exe['vaddr']))
        sshash = ssdeep.hash(binascii.unhexlify(content.strip()))
        rows.append([exe["name"], hex(exe["vaddr"]), hex(exe["size"]),sshash])

    res = {"header": ["Name", "vaddr", "size", "ssdeep"], "rows": rows}

    return res

def help():
    print("""
List EXEs plugin
SYNOPSIS <filename>
This will list executable files in a memory dump, using Radare2/Rizin with 'iSj' looking for '.exe'
 in the section name.
This plugin takes no additional arguments.
""")