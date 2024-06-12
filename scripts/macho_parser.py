"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse Mach-o files.
@details Can supply a section name to extract out of the Mach-o.
By default runs macho_parser_misc()
"""
from deject.plugins import Deject
from kaitaistruct import KaitaiStream, BytesIO
from scripts.extractors.kaitai.mach_o import MachO
from typer import secho,colors
   

@Deject.plugin
def macho_parser():
    """Used to parse information from a Mach-o file"""
    data = MachO.from_file(Deject.file_path)
    if Deject.plugin_args == "False":
            result = macho_parser_misc(data)
    else:
        result = macho_parser_extract(data,Deject.plugin_args)
    return result

def macho_parser_misc(data):
    """Parses information from a Mach-o file, such as Entrypoint and Sections"""
    rows = []
    dylibs = []
    rows.append(["magic",data.magic])
    rows.append(["architecture",data.header.cputype])
    rows.append(["file type",data.header.filetype])
    rows.append(["flags",hex(data.header.flags)])
    rows.append(["number of load commands",data.header.ncmds])
    rows.append(["size of load commands",data.header.sizeofcmds])
    for command in data.load_commands:
        if isinstance(command.body,data.EntryPointCommand):
            rows.append(["entrypoint offset",command.body.entry_off])
            rows.append(["stack size",command.body.stack_size])
        if isinstance(command.body,data.DylibCommand):
            dylibs.append(command.body.name)
        if isinstance(command.body,data.SegmentCommand64):
            for section in command.body.sections:
                rows.append(["section name",section.sect_name])
                rows.append(["segment name",section.seg_name])
                rows.append(["size",section.size])
                rows.append(["address",hex(section.addr)])
    rows.append(["dylib commands", '\n'.join(dylibs)])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def macho_parser_extract(data,args):
    """Extracts sections from a Mach-o file"""
    args = str(Deject.plugin_args).split(" ")
    for command in data.load_commands:
        if isinstance(command.body,data.SegmentCommand64):
            for section in command.body.sections:
                if section.sect_name == args[0]  or section.name == f"__{args[0]}":
                    if isinstance(section.data,data.SegmentCommand64.Section64.StringList):
                        secho(section.data.strings)
                        return
                    if isinstance(section.data,data.SegmentCommand64.Section64.PointerList):
                        secho(section.data.items)
                        return
                    secho(section.data)

def help():
    print("""
Mach-o Parser plugin

SYNOPSIS <filename> [section name]

Uses the Mach-o parser from Kaitai to read information from a Mach-o file.
If a section name is added, extract data from that section.
""")