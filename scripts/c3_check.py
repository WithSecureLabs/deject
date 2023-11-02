"""!
@brief Check if the memory dump or executable is C3.
@details Uses RelayRumbler (https://github.com/ajpc500/RelayRumbler) to extract
configuration from a C3 payload."""
from deject.plugins import Deject
from pathlib import Path
from scripts.helpers import helpers
from sys import exit

@Deject.plugin
def c3_check():
    """Check if the dump corresponds to a F-Secure C3 injected one and extract the config"""
    config_dir = Path("./scripts/extractors/RelayRumbler")
    filename = Deject.file_path
    args = "-f"
    # let's look for yara rules in the config dir
    rules,scripts = helpers.get_rules(helpers, config_dir)
    if len(scripts) == 0:
        print("[Error!] Unable to find parsing script")
        exit(1)
    # for now it is enough that just one rule matches. In future this can be refined if needed
    for script in scripts:
        helpers.script_exec(helpers, script, filename, args)
    return

def help():
    print("""
C3 Plugin

SYNOPSIS <filename>

Uses RelayRumbler (https://github.com/ajpc500/RelayRumbler) to extract
configuration from a C3 payload. This plugin has no additional arguments.
""")