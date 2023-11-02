"""!
@brief Runs PDFiD on a PDF file with the triage plugin. Arguments are [plugin].
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers

@Deject.plugin
def pdf_image():
    """Runs PDFiD on a PDF file with the triage plugin. Arguments are [plugin]."""
    script = Path("./scripts/pdf-tools/pdfid.py")
    filename = Deject.file_path
    if Deject.plugin_args == "False":
         helpers.bin_exec(helpers,["python", script, '-p', './scripts/pdf-tools/plugin_triage', filename])
    else:
        args = str(Deject.plugin_args)
        helpers.bin_exec(helpers,["python", script, '-p', args, filename])
    return

def help():
    print("""
PDF Triage plugin
SYNOPSIS <file> [pdfid plugin]
Uses PDFiD with triage plugin (default)
or runs the named plugin(s) (Separate with comma ',').
""")