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
from enum import Flag

class Flags(Flag):
    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4
    PF_MASKOS = 0x0ff00000
    PF_MASKPROC = 0xf0000000

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
        args = str(Deject.plugin_args).split(" ")
        match args[0]:
            case "extract":
                result = elf_parser_extract(data,args[1])
            case "sections":
                result = elf_parser_sections(data)
            case _:
                result = elf_parser_misc(data)
    return result

def elf_parser_misc(data):
    """Parses an ELF file, to extract section names, entrypoint and flags"""
    rows = []
    rows.append(["ABI Version",data.abi])
    rows.append(["Architecture",data.bits])
    rows.append(["Flags",data.header.flags])
    rows.append(["Section Names",data.header.section_names.entries])
    rows.append(["Entrypoint",data.header.entry_point])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def elf_parser_sections(data):
    rows = []
    for section in data.header.section_headers:
        perms = ""
        rows.append(["Section Name",section.name])
        rows.append(["Section Type",section.type])
        rows.append(["Entry Size",section.entry_size])
        rows.append(["Section Size",section.addr])
        rows.append(["TLS",section.flags_obj.tls])
        flags = elf_parser_flag_lookup(section.flags)
        rows.append(["Flags","\n".join(flags)])
        if section.flags_obj.write:
            perms += "W"
        if section.flags_obj.exec_instr:
            perms += "X"
        if perms != "":
            rows.append(["Permissions",perms])
        rows.append(["Allocated",section.flags_obj.alloc])
        rows.append(["Strings",section.flags_obj.strings])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def elf_parser_flag_lookup(data):
    flags = []
    for i in [e.value for e in Flags]:
        try:
            if data&i > 0:
                flags.append(Flags(data&i).name)
        except ValueError:
            continue
    return flags

def elf_parser_extract(data,args):
    """Extracts sections from an ELF."""
    for section in data.header.section_headers:
        if section.name == args or section.name == f".{args}":
            secho(section.body)

def help():
    print("""
ELF Parser plugin

SYNOPSIS <filename> "[options]"

Uses the ELF parser from Kaitai to read information from an ELF file.
If extract and a section name is added, extract data from that section (enclose options in quotes).
""")