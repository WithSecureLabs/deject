"""!
@brief A plugin to list libraries in a memory dump or PE file.
"""
from deject.plugins import Deject


@Deject.plugin
def lis_libs():
    """List libraries from a PE file or memory dump"""
    libs = Deject.r2_handler.cmdj("ilj")
    results = {"header": ["Library"], "rows": []}
    for lib in libs:
        results["rows"].append([lib.strip().split(" ")[-1]])

    return results


def help():
    print("""
List Libraries plugin

SYNOPSIS <filename>

This plugin is used to list libraries in a PE file or memory dump by running Radare/Rizin with the 'ilj' command.
""")
