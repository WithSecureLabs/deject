"""!
@brief Uses 1768.py to check if the memory dump or PE has Cobalt Strike configuration.
"""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers


@Deject.plugin
def cobaltstrike_check():
    """Check if the dump corresponds to a cs injected one and extract the config"""
    process = ["python",Path("./scripts/extractors/cobaltstrike/1768.py")]
    filename = [Deject.file_path]
    arg = Deject.plugin_args
    if arg == "False":
        helpers.bin_exec(helpers,process + filename)
    else:
        helpers.bin_exec(helpers,process + arg.strip().split(" ") + filename)