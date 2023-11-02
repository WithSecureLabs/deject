"""!
@brief Uses radare/rizin to extract imports for a PE file.
"""
from deject.plugins import Deject
from typer import secho,colors

@Deject.plugin
def pe_imports():
    """List imports in a PE file."""
    imports = Deject.r2_handler.cmdj("iij")
    if imports is None: 
        secho("No imports detected in the file, this might be a bug!", fg=colors.RED)
        return
    rows = []
    for imp in imports:
        try:
            rows.append([imp["name"],imp["libname"]])
        except:
            rows.append([imp["name"]])
    res = {"header": ["Name","Library"], "rows": rows}

    return res

def help():
    print("""
PE Imports plugin
SYNOPSIS <filename>
Use Radare2/Rizin with the 'iij' command to list imports in a PE file or memory dump.
There are no additional arguments for this plugin.
""")
