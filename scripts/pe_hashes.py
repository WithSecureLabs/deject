"""!
@brief Get imphash, Rich hash, TLSH and ssdeep of executable and output Virus Total links.
@details Can also support a memory dump with the base address of the memory region to extract
in decimal.
"""
from deject.plugins import Deject
import pefile
import ssdeep
from typer import secho, colors
import tlsh
from hashlib import md5


def get_rich_header_hash(pe):
    if not hasattr(pe, "RICH_HEADER") or pe.RICH_HEADER is None:
        return ""

    return md5(pe.RICH_HEADER.clear_data).hexdigest()


@Deject.plugin
def pe_hashes():
    """Get imphash, Rich hash, TLSH and ssdeep of executable (if given a memory dump, pass in the base address of memory to extract with Radare2)"""
    filename = Deject.file_path
    with open(filename, "rb") as f:
        data = f.read()
    try:
        pe = pefile.PE(data=data)
    except:
        base_addr = Deject.plugin_args
        if base_addr == "False":
            secho(
                "Please enter a decimal base address of a section to extract! Run:\npoetry run deject run --include pe_hashes /path/to/dump.dmp <baseaddr>.",
                fg=colors.RED,
            )
            return
        sections = Deject.r2_handler.cmdj("iSj")
        if sections is None:
            secho("No sections detected in the dump, this might be a bug!", fg=colors.RED)
            return
        sect = 0
        size = 0
        for section in sections:
            if section["vaddr"] == int(base_addr):
                sect, size = hex(int(section["vaddr"])), section["size"]
        if size == 0:
            secho(
                f"Section {base_addr} not found in dump! Try using inspect_mmaps if this was an injected process.", fg=colors.RED,
            )
            return
        try:
            pe = bytes.fromhex(Deject.r2_handler.cmd(f"p8 {size} @{sect}"))
            pe = pefile.PE(data=pe)
        except Exception as err:
            secho(f"Failed to read PE file from dump: {err}", fg=colors.RED)
            return
    if hasattr(pe, "get_imphash"):
        imp = pe.get_imphash()
        if len(imp) > 0:
            print(f"https://www.virustotal.com/gui/search/imphash:{imp}")
    if hasattr(pe, "get_rich_header_hash"):
        header_hash = pe.get_rich_header_hash()
        if len(header_hash) > 0:
            print(
                f"https://www.virustotal.com/gui/search/rich_pe_header_hash:{header_hash}",
            )
    else:
        header_hash = get_rich_header_hash(pe)
        if len(header_hash) > 0:
            print(
                f"https://www.virustotal.com/gui/search/rich_pe_header_hash:{header_hash}",
            )
    print(
        f'https://www.virustotal.com/gui/search/ssdeep%253A%2522{ssdeep.hash(data).replace("/", "%252F").replace(":", "%253A").replace("+", "%252B")}%2522',
    )
    print(f"https://www.virustotal.com/gui/search/tlsh:{tlsh.hash(data)}")


def help():
    print("""
PE Hashing Plugin
SYNOPSIS <filename> [baseaddress]
This plugin will printout VirusTotal URLs for Rich PE Header, SSDEEP and TLSH hashes.
If the input is a MDMP file a base address for the executable is needed, in decimal format.
The plugin does not require a Virus Total API key, as the Virus Total API is not used.
          """)
