"""!
@brief List exports of a PE file.
@details This could be useful if analysing a DLL.
"""
from deject.plugins import Deject

@Deject.plugin
def pe_exports():
    """List exports in a PE file."""
    exports = Deject.r2_handler.cmdj("iEj")
    if exports is None: 
        print("No exports detected in the file, this might be a bug!")
        return
    rows = []
    for exp in exports:
        rows.append([exp["name"]])
    res = {"header": ["Name"], "rows": rows}

    return res

def help():
    print("""
PE Exports plugin
SYNOPSIS <filename>
Use Radare2/Rizin with the 'iEj' command to list exports in a PE file or memory dump.
There are no additional arguments for this plugin.
""")
