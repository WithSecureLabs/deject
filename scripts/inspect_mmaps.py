"""!
@brief Inspect mapped regions of memory, especially for privately mapped rwx or r-x regions."""
from deject.plugins import Deject
import math
import collections
import pefile
import ssdeep
import binascii
from hashlib import md5
from pathlib import Path
from typer import secho,colors


savedir = Path("./save")

def get_rich_header_hash(content):
    try:
        pe = pefile.PE(data=content)
        if not hasattr(pe, "RICH_HEADER") or pe.RICH_HEADER is None:
            return ""

        return md5(pe.RICH_HEADER.clear_data).hexdigest()
    except:
        return "DOS Magic Header not found"


def entropy(data):
    e = 0
    counter = collections.Counter(data)
    l = len(data)
    for count in counter.values():
        p_x = count / l
        e += - p_x * math.log2(p_x)
    return round(e, 5)


def inspct_mmaps(mmaps):

    pages = []

    for mmap in mmaps:
        map_type = mmap["name"].split(' ')[2].split('=')[1]
        map_addr = hex(abs(int(mmap["address"])))
        if mmap["flags"] == "rwx" and int(map_type, 16) == int("0x20000", 16):
            pages.append([map_addr, hex(mmap["size"]), mmap["flags"]])
        elif mmap["flags"] == "r-x" and int(map_type, 16) == int("0x20000", 16):
            pages.append([map_addr, hex(mmap["size"]), mmap["flags"]])            
    return pages


def enrich(maps):
    for page in maps:
        
        content = Deject.r2_handler.cmd("p8 {} @ {}".format(page[1], page[0]))
        i = maps.index(page)
        maps[i].append([])
        if "4d5a" in content: 
            maps[i][-1].append("MZ")
        if "5045" in content:
            maps[i][-1].append("PE")
            
        maps[i].append(entropy(content))
        maps[i].append(ssdeep.hash(binascii.unhexlify(content.strip())))
        maps[i].append(get_rich_header_hash(bytes.fromhex(content.strip())))
    return maps


@Deject.plugin
def mmaps_report():
    """Look for privately mapped mempages with RWX permissions."""
    mmaps = Deject.r2_handler.cmdj("imj")
    mmap_cands = inspct_mmaps(mmaps)
    if len(mmap_cands) != 0:
        secho("Privately mapped memory pages with interesting permissions found!",fg=colors.GREEN)
        enriched = enrich(mmap_cands)
        res = {"header": ["vaddr", "size", "perms", "headers", "entropy", "ssdeep", "Rich Header Hash"], "rows": enriched}
        return res
    else:
        secho("No privately mapped RWX pages could be found!", fg=colors.RED)

def help():
    print("""
Inspect MMaps Plugin
SYNOPSIS <filename>
Inspect the Memory Maps for a memory dump, especially for RX or RWX permissions.
This uses Radare2/Rizin with the 'imj' command.
This plugin takes no additional arguments.
""")