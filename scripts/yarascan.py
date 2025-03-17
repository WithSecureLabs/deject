"""!
@brief Use yara-python to scan a file or memory dump.
"""

from pathlib import Path
from deject.plugins import Deject
from scripts.helpers import helpers, Settings
import os

rules_path = Path("./scripts/yara-rules/yara/rules")


@Deject.plugin
def run_yara():
    """Run a set of yara rules on the memory dump."""
    yara_dir = Settings().getSetting("yara_rule")
    rule_path = rules_path
    if yara_dir != "":
        rule_path = Path(os.path.expanduser(yara_dir))
    matches = []

    for rule in rule_path.iterdir():
        if rule.suffix == ".yara" or rule.suffix == ".yar":
            rule = str(rule)
            try:
                match = helpers.yara_exec(helpers, rule, Deject.file_path)
            except:
                raise Exception(f"Error in rule {rule}")
            if len(match) > 0:
                matches.append(match)

    if len(matches) != 0:
        return matches


def help():
    print("""
Yara Scan plugin
SYNOPSIS <filename>
Run Yara Python on a file. By default this uses rules located in the yara-rules directory.
To change the rules used during the scan, set the RULES environment variable to where the
.yar files reside.
This plugin has no additional arguments.
""")
