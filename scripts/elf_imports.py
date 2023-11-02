"""!
@brief Uses radare/rizin to extract imports for an ELF file.
"""
from deject.plugins import Deject
from typer import secho,colors

@Deject.plugin
def pe_imports():
    """List imports in an ELF file."""
    imports = Deject.r2_handler.cmdj("iij")
    if imports is None: 
        secho("No imports detected in the file, this might be a bug!", fg=colors.RED)
        return
    rows = []
    for imp in imports:
        rows.append([imp["name"]])
    res = {"header": ["Name"], "rows": rows}

    return res

def help():
    print("""
ELF Imports plugin
SYNOPSIS <filename>
Use Radare2/Rizin with the 'iij' command to list imports in an ELF file.
There are no additional arguments for this plugin.
""")