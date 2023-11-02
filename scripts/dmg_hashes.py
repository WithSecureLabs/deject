"""!
@brief print DMG TLSH hash
"""
from deject.plugins import Deject
import tlsh

@Deject.plugin
def elf_hashes():
    """Print TLSH hash of a DMG file"""
    with open(Deject.file_path, "rb") as f:
        data = f.read()
        hashes = tlsh.hash(data)
        res = {"header": ["Filename","TLSH"], "rows": [[Deject.file_path,hashes]]}
        return res

def help():
    print("""
DMG Hashes plugin
SYNOPSIS <filename>
Print the TLSH of a DMG file.
There are no additional arguments for this plugin.
""")