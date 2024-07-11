"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse Mach-o files.
@details Can supply a section name to extract out of the Mach-o.
By default runs macho_parser_misc()
"""
from deject.plugins import Deject
from kaitaistruct import KaitaiStream, BytesIO
from scripts.extractors.kaitai.mach_o import MachO
from typer import secho,colors
from enum import Flag

class Flags(Flag):
    MH_NOUNDEFS = 0x1
    MH_INCRLINK = 0x2
    MH_DYLDLINK = 0x4
    MH_BINDATLOAD = 0x8
    MH_PREBOUND = 0x10
    MH_SPLIT_SEGS = 0x20
    MH_LAZY_INIT = 0x40
    MH_TWOLEVEL = 0x80
    MH_FORCE_FLAT = 0x100
    MH_NOMULTIDEFS = 0x200
    MH_NOFIXPREBINDING = 0x400
    MH_PREBINDABLE  = 0x800
    MH_ALLMODSBOUND = 0x1000
    MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000
    MH_CANONICAL = 0x4000
    MH_WEAK_DEFINES = 0x8000
    MH_BINDS_TO_WEAK = 0x10000	
    MH_ALLOW_STACK_EXECUTION = 0x20000
    MH_ROOT_SAFE = 0x40000             
    MH_SETUID_SAFE = 0x80000
    MH_NO_REEXPORTED_DYLIBS = 0x100000 
    MH_PIE = 0x200000			
    MH_DEAD_STRIPPABLE_DYLIB = 0x400000 
    MH_HAS_TLV_DESCRIPTORS = 0x800000
    MH_NO_HEAP_EXECUTION = 0x1000000
    MH_APP_EXTENSION_SAFE = 0x02000000
    MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x04000000
    MH_SIM_SUPPORT = 0x08000000

class SegFlags(Flag):
    SG_HIGHVM = 0x1
    SG_FVMLIB = 0x2
    SG_NORELOC = 0x4
    SG_PROTECTED_VERSION_1 = 0x8
   

@Deject.plugin
def macho_parser():
    """Used to parse information from a Mach-o file"""
    data = MachO.from_file(Deject.file_path)
    args = str(Deject.plugin_args).split(" ")
    match args[0]:
        case "extract":
            result = macho_parser_extract(data,args[1])
        case "sections":
            result = macho_parser_sections(data)
        case _:
            result = macho_parser_misc(data)
           
    return result

def macho_parser_misc(data):
    """Parses information from a Mach-o file, such as Entrypoint and Sections"""
    rows = []
    rows.append(["Magic",data.magic])
    rows.append(["Architecture",data.header.cputype])
    rows.append(["File Type",data.header.filetype])
    rows.append(["Flags (raw)",hex(data.header.flags)])
    flags = macho_parser_flags_lookup(data.header.flags)
    rows.append(["Flags", "\n".join(flags)])
    rows.append(["Number of Load Commands",data.header.ncmds])
    rows.append(["Size of Load Commands",data.header.sizeofcmds])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def macho_parser_sections(data):
    rows = []
    dylibs = []
    for command in data.load_commands:
        if isinstance(command.body,data.DylinkerCommand):
            rows.append(["Dylinker Command",command.body.name.value])
        if isinstance(command.body,data.EntryPointCommand):
            rows.append(["Section Type",command.type.name])
            rows.append(["Entrypoint Offset",command.body.entry_off])
            rows.append(["Stack Size",command.body.stack_size])
        if isinstance(command.body,data.DylibCommand):
            rows.append(["Section Type",command.type.name])
            dylibs.append(command.body.name)
        if isinstance(command.body,data.SegmentCommand64):
            for section in command.body.sections:
                rows.append(["Flags (raw)",section.flags])
                rows.append(["Flags","\n".join(macho_parser_seg_flags_lookup(section.flags))])
                rows.append(["Section Type",command.type.name])
                rows.append(["Section Name",section.sect_name])
                rows.append(["Segment Name",section.seg_name])
                rows.append(["Size",section.size])
                rows.append(["Address",hex(section.addr)])
    rows.append(["Dylib Commands", '\n'.join(dylibs)])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def macho_parser_flags_lookup(data):
    flags = []
    for i in [e.value for e in Flags]:
        try:
            if data&i > 0:
                flags.append(Flags(data&i).name)
        except ValueError:
            continue
    return flags

def macho_parser_seg_flags_lookup(data):
    flags = []
    for i in [e.value for e in SegFlags]:
        try:
            if data&i > 0:
                flags.append(SegFlags(data&i).name)
        except ValueError:
            continue
    return flags

def macho_parser_extract(data,args):
    """Extracts sections from a Mach-o file"""
    try:
        for command in data.load_commands:
            if isinstance(command.body,data.SegmentCommand64):
                for section in command.body.sections:
                    if section.sect_name == args  or section.sect_name == f"__{args}":
                        if isinstance(section.data,data.SegmentCommand64.Section64.StringList):
                            secho(section.data.strings)
                            return
                        if isinstance(section.data,data.SegmentCommand64.Section64.PointerList):
                            secho(section.data.items)
                            return
                        secho(section.data)
    except UnicodeDecodeError:
        secho(f"Could not decode data for section {args}!",fg=colors.RED)

def help():
    print("""
Mach-o Parser plugin

SYNOPSIS <filename> "[options]"

Uses the Mach-o parser from Kaitai to read information from a Mach-o file.
If extract and a section name is added, extract data from that section (enclose additional options in quotes).
""")