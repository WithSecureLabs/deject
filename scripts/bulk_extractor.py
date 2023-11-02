"""! @brief This plugin runs Bulk Extractor on a file. To run the plugin, type
poetry run deject run --include bulk_extractor \<file\>. This plugin has no arguments
and will save output to a directory 'extracted/' in the location of the file.
Download Bulk_Extractor and link or copy the binary to bin/ in Deject's root directory."""

from deject.plugins import Deject
import os
from scripts.helpers import helpers,Settings


@Deject.plugin
def bulk_extractor():
    """Use bulk_extractor on the memory dump."""
    filename = Deject.file_path
    filepath = os.path.dirname(Deject.file_path)
    bulk = f"{os.path.dirname(os.path.realpath(__file__))}/../bin/bulk_extractor"
    if not os.path.exists(bulk):
        if Settings().getSetting("bulk_path"):
            bulk = Settings().getSetting("bulk_path")
        else:
            bulk = "bulk_extractor"
    helpers.bin_exec(helpers,[bulk, "-o", f"{filepath}/extracted", "-0", filename])

def help():
    print("""
Bulk Extractor Plugin
SYNOPSIS <filename>

Runs Bulk Extractor on the file supplied, with default arguments. This plugin takes no additional arguments.
Download Bulk_Extractor and link or copy the binary to bin/ in Deject's root directory.
""")
