"""!
@brief print ELF hashes (TELFHASH)
"""
from deject.plugins import Deject
from telfhash import telfhash


@Deject.plugin
def elf_hashes():
    """Print TELFHASH of ELF"""
    hashes = telfhash(Deject.file_path)
    hashes = list(hashes[0].values())
    res = {"header": ["Filename", "Telfhash", "message"], "rows": [hashes]}
    return res


def help():
    print("""
ELF Hashes plugin
SYNOPSIS <filename>
Print the TELFHash of an ELF file.
There are no additional arguments for this plugin.
""")
