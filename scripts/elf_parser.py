"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse ELF files.
@details Can supply a section name to extract out of the ELF.
By default runs elf_parser_misc()
"""
from deject.plugins import Deject
from kaitaistruct import KaitaiStream, BytesIO
from scripts.extractors.kaitai.elf import Elf
from pathlib import Path
from typer import secho,colors

@Deject.plugin
def elf_parser():
    """Used to parse information from a ELF file"""
    with open(Deject.file_path,"rb") as hfile:
        try:
            data = Elf(KaitaiStream(BytesIO(hfile.read())))
        except Exception:
            try:
                hfile.seek(0)
                data = Elf(KaitaiStream(BytesIO(b"\x7f"+hfile.read())))
            except Exception:
                secho(f"Could not open file {Deject.file_path} as an Elf file.", fg=colors.RED)
                return
        if Deject.plugin_args == "False":
            result = elf_parser_misc(data)
        else:
            result = elf_parser_extract(data,Deject.plugin_args)
    return result

def elf_parser_misc(data):
    """Parses an ELF file, to extract section names, entrypoint and flags"""
    rows = []
    rows.append(["abi version",data.abi])
    rows.append(["architecture",data.bits])
    rows.append(["flags",data.header.flags])
    rows.append(["section names",data.header.section_names.entries])
    rows.append(["entrypoint",data.header.entry_point])
    for section in data.header.section_headers:
        perms = ""
        rows.append(["section name",section.name])
        rows.append(["entry size",section.entry_size])
        rows.append(["section size",section.addr])
        rows.append(["TLS",section.flags_obj.tls])
        if section.flags_obj.write:
            perms += "W"
        if section.flags_obj.exec_instr:
            perms += "X"
        if perms != "":
            rows.append(["permissions",perms])
        rows.append(["allocated",section.flags_obj.alloc])
        rows.append(["strings",section.flags_obj.strings])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def elf_parser_extract(data,args):
    """Extracts sections from an ELF."""
    args = str(Deject.plugin_args).split(" ")
    for section in data.header.section_headers:
        if section.name == args[0] or section.name == f".{args[0]}":
            secho(section.body)

def help():
    print("""
ELF Parser plugin

SYNOPSIS <filename> [section name]

Uses the ELF parser from Kaitai to read information from an ELF file.
If a section name is added, extract data from that section.
""")