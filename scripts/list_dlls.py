"""!
@brief List DLLs in a memory dump and check for duplicates.
@details Duplicates could indicate an anomaly.
"""
from deject.plugins import Deject
import ssdeep
import binascii


def extract(sections):
    dlls = []
    for s in sections:
        if s["name"][-4:] == ".dll":
            dlls.append(s)
    return dlls


@Deject.plugin
def list_dlls():
    """List the dlls in the memory dump. Highlight if there are duplicates."""
    sections = Deject.r2_handler.cmdj("iSj~dll")
    if sections is None:
        print("No dlls detected in the dump, this might be a bug!")
        return
    dlls = extract(sections)
    rows = []

    # check for duplicates
    dlls1 = set()
    for i in dlls:
        dlls1.add(i["name"])
    if len(dlls) > len(dlls1):
        print("Duplicate dlls detected!")
        matches = [element for element in dlls if element in dlls1]
        print(matches)

    for d in dlls:
        content = Deject.r2_handler.cmd(
            "p8 {} @ {}".format(d['size'], d['vaddr']),
        )
        sshash = ssdeep.hash(binascii.unhexlify(content.strip()))
        if (d["name"].split("\\")[2].casefold() != "system32".casefold()) and (d["name"].split("\\")[2].casefold() != "syswow64".casefold()):
            rows.append([
                d["name"], hex(d["vaddr"]),
                hex(d["size"]), "X", sshash,
            ])
        elif not Deject.quiet:
            rows.append([
                d["name"], hex(d["vaddr"]),
                hex(d["size"]), " ", sshash,
            ])

    res = {
        "header": [
            "Name", "vaddr", "size",
            "anomalous", "ssdeep",
        ], "rows": rows,
    }

    return res


def help():
    print("""
List DLLs plugin
SYNOPSIS <filename>

This plugin will print DLLs from a memory dump using Radare/Rizin 'iSj~dll'.
It will also print duplicated DLLs in the memory dump.
This plugin has no additional arguments.
""")
