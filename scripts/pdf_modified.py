"""!
@brief Uses pdftool.py to check if the PDF has been modified.
@details Can also extract the modifications if the ID of the modification supplied.
A filename where the modification is saved is optional."""
from deject.plugins import Deject
from pathlib import Path
import os
from scripts.helpers import helpers

@Deject.plugin
def pdf_modified():
    """Check if a PDF file has been modified. Dump the modification with "<id> [filename]"."""
    script = Path("./scripts/pdf-tools/pdftool.py")
    filename = Deject.file_path
    args = "iu"
    if Deject.plugin_args == "False":
        helpers.script_exec(helpers, script, filename, args)
    else:
        addargs = str(Deject.plugin_args).split(" ")
        select = int(addargs[0])
        if len(addargs) == 1:
            helpers.bin_exec(helpers,["python", script, args, f"-s {select}", filename])
        else:
            helpers.bin_exec(helpers,["python", script, args, f"-s {select}", "-o", os.path.expanduser(addargs[1].strip()), filename])
    return

def help():
    print("""
PDF Modified plugin
SYNOPSIS <file> [id] [output]
Uses pdftool.py to check if the PDF has been modified.
Without the ID number, all modifications for the PDF are displayed.
Can also extract the modifications if the ID of the modification supplied.
A filename where the modification is saved is optional.       
""")
