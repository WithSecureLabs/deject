"""!
@brief Uses oledump.py and initially runs info. Can be used with arguments to allow for additional plugins, such as plugin_msi_info or plugin_vbaproject.
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers


@Deject.plugin
def ole_analytics():
    """Use oledump to analyse an OLE file, initially runs info"""
    script = Path("./scripts/ole-tools/oledump.py")
    filename = Deject.file_path
    if Deject.plugin_args == "False":
        helpers.bin_exec(helpers, ["python", script, filename])
    else:
        args = str(Deject.plugin_args)
        helpers.bin_exec(
            helpers, [
                "python", script, "--plugindir=./scripts/ole-tools/",
            ] + args.strip().split(" ") + [filename],
        )
    return


def help():
    print("""
OLE Analytics Plugin
SYNOPSIS <filename> [arguments]
Uses oledump and initially runs the info command.
Arguments to this plugin will be passed to oledump, this includes using additional plugins.
Add plugins to the ole-tools folder.
""")
