"""!
@brief Uses pdf2image to save the PDF as a JPEG.
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers
import os


@Deject.plugin
def pdf_image():
    """Convert a PDF to an image using the pdftoimage file. Arguments are [output]."""
    script = Path("./scripts/pdf-tools/pdftojpg.py")
    filename = Deject.file_path
    filepath = os.path.dirname(Deject.file_path)
    if Deject.plugin_args == "False":
        helpers.bin_exec(helpers, ["python", script, filename, filepath])
        print(f"[+] Saved image to {filepath}")
    else:
        args = str(Deject.plugin_args).split(" ")
        helpers.bin_exec(helpers, ["python", script, filename, args[0]])
        print(f"[+] Saved image to {args[0]}")
    return


def help():
    print("""
PDF Image plugin
SYNOPSIS <file> [output]
Uses pdftojpg.py to convert a PDF to a JPEG file.
If an output location is provided, the files are saved in that location.
Default is saving the images in the same location as the file.
""")
