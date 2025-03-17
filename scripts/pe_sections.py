"""!
@brief This plugin handles sections of a PE file and can carve or show only abnormal sections.
@details Without arguments, this plugin will show all sections of a PE file and generate an SSDEEP hash of the section.
Carving of sections is also possible by running the plugin with the arguments "carve <sectionname>", for example
poetry run deject run --include pe_sections \<file\> "carve .text". The carved section is saved to the same
location as the file.
"""
from deject.plugins import Deject
import ssdeep
import binascii
import os
from typer import secho, colors

# list of normal sections
NORMALSEC = [
    ".text", ".pdata", ".rsrc", ".reloc", ".data", ".rdata",
    ".bss", ".sbss", ".sdata", ".sxdata", ".tls", ".xdata", ".vsdata",
]


@Deject.plugin
def pe_sections():
    """Check the sections of a PE file and give a fuzzy hash of the section.
Use "carve <sectionname>" to carve a section to disk."""
    rows = []
    sections = Deject.r2_handler.cmdj("iSj")
    args = Deject.plugin_args.split(" ")
    if args[0] == "carve":
        for sec in sections:
            if sec['name'] == args[1]:
                content = Deject.r2_handler.cmd(
                    "p8 {} @ {}".format(sec['size'], sec['vaddr']),
                )
                sshash = ssdeep.hash(binascii.unhexlify(content.strip()))
                filepath = os.path.dirname(Deject.file_path)
                f = open(filepath + "/" + sec["name"], "wb")
                f.write(binascii.unhexlify(content.strip()))
                f.close()
                secho(
                    f"[+] Saved section {sec['name']} to {filepath}", fg=colors.GREEN,
                )
                rows.append([
                    sec['name'], hex(sec['vaddr']),
                    hex(sec['vsize']), sshash,
                ])
    else:
        for sec in sections:
            if Deject.quiet:
                if sec['name'] in NORMALSEC:
                    continue
            content = Deject.r2_handler.cmd(
                "p8 {} @ {}".format(sec['size'], sec['vaddr']),
            )
            sshash = ssdeep.hash(binascii.unhexlify(content.strip()))
            rows.append([
                sec['name'], hex(sec['vaddr']),
                hex(sec['vsize']), sshash,
            ])
    res = {"header": ["Name", "vaddr", "size", "ssdeep"], "rows": rows}
    return res


def help():
    print("""
PE Sections plugin
SYNOPSIS <filename> "carve <sectionname>"
Shows all sections of a PE file.
Quiet mode will only return abnormal section names.
If "carve <sectionname>" is passed, the section will be carved out of the PE file.
Remember the quotes.
SSDEEP hashes for the sections are also returned.
""")
