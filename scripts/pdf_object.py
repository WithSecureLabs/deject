"""!
@brief Use pdf-parser to extract an object from a PDF. Run with object ID as the argument.
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers

@Deject.plugin
def pdf_object():
    """Use pdf-parser to parse objects. Uses "-o -c -w" options."""
    script = Path("./scripts/pdf-tools/pdf-parser.py")
    filename = Deject.file_path
    object = Deject.plugin_args
    helpers.bin_exec(helpers,["python", script, "-o", object, "-c", "-w", filename])
    return

def help():
    print("""
PDF Object plugin
SYNOPSIS <file> <objectid>
Uses pdf-parser.py to extract an object from the PDF file.
Can also extract the modifications if the ID of the modification supplied.
A filename where the modification is saved is optional.       
""")

