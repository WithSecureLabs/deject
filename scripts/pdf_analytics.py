"""!
@brief Uses pdf-parser.py to display stats of keywords in a PDF.
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers


@Deject.plugin
def pdf_analytics():
    """Use pdf-parser to search keywords, this uses "-a -O"."""
    script = Path("./scripts/pdf-tools/pdf-parser.py")
    filename = Deject.file_path
    helpers.bin_exec(helpers, ["python", script, "-a", "-O", filename])
    return


def help():
    print("""
PDF Analytics Plugin
SYNOPSIS <filename>
Uses pdf-parser with the '-a -O' arguments to list stats of keywords used in a PDF.
This plugin takes no additional arguments.
""")
