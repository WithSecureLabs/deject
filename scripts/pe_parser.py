"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse PE files.
@details Can supply a section name to extract out of the PE.
By default runs pe_parser_misc()
"""
from deject.plugins import Deject
from kaitaistruct import KaitaiStream, BytesIO
from scripts.extractors.kaitai.microsoft_pe import MicrosoftPe
from datetime import datetime,timezone
from typer import secho,colors
   

@Deject.plugin
def pe_parser():
    """Used to parse information from a PE file"""
    data = MicrosoftPe.from_file(Deject.file_path)
    if Deject.plugin_args == "False":
        result = pe_parser_misc(data)
    else:
        result = pe_parser_extract(data,Deject.plugin_args)
    return result

def pe_parser_misc(data):
    """Parses information from a PE file, such as sections and certificates"""
    rows = []
    for section in data.pe.sections:
        rows.append(["section",section.name])
        rows.append(["virtual size",section.virtual_size])
        rows.append(["raw data size",section.size_of_raw_data])
        rows.append(["virtual address",hex(section.virtual_address)])
        rows.append(["section characteristics",hex(section.characteristics)])
    rows.append(["architecture",data.pe.coff_hdr.machine])
    rows.append(["pe characteristics",hex(data.pe.coff_hdr.characteristics)])
    rows.append(["timestamp",datetime.fromtimestamp(data.pe.coff_hdr.time_date_stamp,timezone.utc).strftime("%Y-%m-%d %H:%M:%S")])
    if isinstance(data.pe.certificate_table, data.CertificateTable):
        for cert in data.pe.certificate_table.items:
            rows.append(["certificate",cert.certificate_bytes])
            rows.append(["type",cert.certificate_type])
            rows.append(["revision",cert.revision])
            rows.append(["length",cert.length])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def pe_parser_extract(data,args):
    """Extracts sections from a PE file"""
    args = str(Deject.plugin_args).split(" ")
    for section in data.pe.sections:
        if section.name == args[0] or section.name == f".{args[0]}":
            secho(section.body.decode(u"UTF-8", errors="ignore"))

def help():
    print("""
PE Parser plugin

SYNOPSIS <filename> [section name]

Uses the PE parser from Kaitai to read information from a PE file.
If a section name is added, extract data from that section.
""")
