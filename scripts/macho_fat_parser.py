"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse Mach-o Fat files.
@details Can supply a section name to extract out of the Mach-o Fat.
By default runs macho_parser_misc() from macho_parser plugin
"""
from deject.plugins import Deject
from kaitaistruct import KaitaiStream, BytesIO
from scripts.extractors.kaitai.mach_o_fat import MachOFat
import scripts.macho_parser
from typer import secho,colors
from enum import Flag

@Deject.plugin
def macho_fat_parser():
    """Used to parse information from a Mach-o file"""
    data = MachOFat.from_file(Deject.file_path)
    args = str(Deject.plugin_args).split(" ")
    if args[0] == "False":
        secho(f"Please select a CPU Arch from the following: {[x.cpu_type.name for x in data.fat_archs]})")
        return
    args.append("")
    for archs in data.fat_archs:
        if archs.cpu_type.name == args[0]:
            match args[1]:
                case "extract":
                    result = scripts.macho_parser.macho_parser_extract(archs.object,args[2])
                case "sections":
                    result = scripts.macho_parser.macho_parser_sections(archs.object)
                case _:
                    result = scripts.macho_parser.macho_parser_misc(archs.object)
    return result

def help():
    print("""
Mach-o Fat Parser plugin

SYNOPSIS <filename> "[options]"

Select the Architecture to get information about, running without the architechure will print available architectures in the file.

Uses the Mach-o Fat parser from Kaitai to read information from a Mach-o Fat file.
If extract and a section name is added, extract data from that section (enclose additional options in quotes).
""")