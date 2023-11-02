"""!
@brief Extract PoshC2 (https://github.com/nettitude/PoshC2) configurations from memory dumps or PE files.
@details If a file or memory dump is expected to be PoshC2, run this plugin to extract the configuration.
This uses poshc2parser.py and Chepy (https://github.com/securisec/chepy).
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers

@Deject.plugin
def poshc2_check():
    """Check if the dump corresponds to a PoshC2 injected one and extract the config"""
    script = Path("./scripts/extractors/poshc2Parser/poshc2parser.py")
    filename = Deject.file_path
    arg = "-f"
    helpers.script_exec(helpers, script, filename, arg)

def help():
    print("""
PoshC2 Check plugin
SYNOPSIS <filename>
Run the PoshC2 parser on a memory dump or PE file and extract the configuration.
The plugin uses the Chepy module.
This plugin takes no additional arguments.
""")