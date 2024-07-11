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
from enum import Flag
import ssdeep
import binascii
import os

class PeCharact(Flag):
    IMAGE_FILE_RELOCS_STRIPPED = 0x1
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x2
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x10
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20
    IMAGE_FILE_BYTES_REVERSED_LO = 0x80
    IMAGE_FILE_32BIT_MACHINE = 0x100
    IMAGE_FILE_DEBUG_STRIPPED = 0x200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000

class SectCharact(Flag):
    IMAGE_SCN_TYPE_NO_PAD = 0x8
    IMAGE_SCN_CNT_CODE = 0x20
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80
    IMAGE_SCN_LNK_OTHER = 0x100
    IMAGE_SCN_LNK_INFO = 0x200
    IMAGE_SCN_LNK_REMOVE = 0x800
    IMAGE_SCN_LNK_COMDAT = 0x1000
    IMAGE_SCN_GPREL = 0x8000
    IMAGE_SCN_MEM_PURGEABLE = 0x20000
    IMAGE_SCN_MEM_16BIT = 0x20000
    IMAGE_SCN_MEM_LOCKED = 0x40000
    IMAGE_SCN_MEM_PRELOAD = 0x80000
    IMAGE_SCN_ALIGN_1BYTES = 0x100000
    IMAGE_SCN_ALIGN_2BYTES = 0x200000
    IMAGE_SCN_ALIGN_4BYTES = 0x300000
    IMAGE_SCN_ALIGN_8BYTES = 0x400000
    IMAGE_SCN_ALIGN_16BYTES = 0x500000
    IMAGE_SCN_ALIGN_32BYTES = 0x600000
    IMAGE_SCN_ALIGN_64BYTES = 0x700000
    IMAGE_SCN_ALIGN_128BYTES = 0x800000
    IMAGE_SCN_ALIGN_256BYTES = 0x900000
    IMAGE_SCN_ALIGN_512BYTES = 0xA00000
    IMAGE_SCN_ALIGN_1024BYTES = 0xB00000
    IMAGE_SCN_ALIGN_2048BYTES = 0xC00000
    IMAGE_SCN_ALIGN_4096BYTES = 0xD00000
    IMAGE_SCN_ALIGN_8192BYTES = 0xE00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x1000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x2000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x4000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x8000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

class DllCharact(Flag):
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x20
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000



@Deject.plugin
def pe_parser():
    """Used to parse information from a PE file"""
    data = MicrosoftPe.from_file(Deject.file_path)
    args = str(Deject.plugin_args).split(" ")
    match args[0]:
        case "extract":
            result = pe_parser_extract(data,args[1])
        case "certificate":
            result = pe_parser_certificate(data)
        case "sections":
            result = pe_parser_sections(data)
        case "datadirs":
            result = pe_parser_datadirs(data)
        case "extract_datadir":
            result = pe_parser_extract_datadir(data,args[1])
        case _: 
            result = pe_parser_misc(data)
    return result

def pe_parser_misc(data):
    """Parses information from a PE file"""
    rows = []
    try:
        rows.append(["Architecture",data.pe.coff_hdr.machine])
        rows.append(["PE Format",data.pe.optional_hdr.std.format])
        rows.append(["PE Characteristics (raw)",hex(data.pe.coff_hdr.characteristics)])
        characts = pe_parser_pe_char_lookup(data.pe.coff_hdr.characteristics)
        rows.append(["PE Characteristics","\n".join(characts)])
        rows.append(["Subsystem",data.pe.optional_hdr.windows.subsystem]) 
        rows.append(["Timestamp",datetime.fromtimestamp(data.pe.coff_hdr.time_date_stamp,timezone.utc).strftime("%Y-%m-%d %H:%M:%S")])
        rows.append(["DLL Characteristics (raw)",hex(data.pe.optional_hdr.windows.dll_characteristics)])
        dllcharacts = pe_parser_dll_char_lookup(data.pe.optional_hdr.windows.dll_characteristics)
        rows.append(["DLL Characteristics","\n".join(dllcharacts)])
        if image64 := getattr(data.pe.optional_hdr.windows,"image_base_64",False):
            rows.append(["Base Address",hex(image64)])
        else:
            rows.append(["Base Address",hex(data.pe.optional_hdr.windows.image_base_32)])
        rows.append(["Entrypoint",hex(data.pe.optional_hdr.std.address_of_entry_point)])
        rows.append(["Base of Code",hex(data.pe.optional_hdr.std.base_of_code)])
        if baseData := getattr(data.pe.optional_hdr.std,"base_of_data",False):
            rows.append(["Base of Data",hex(baseData)])
        if isinstance(data.pe.certificate_table,data.CertificateTable):
            for cert in data.pe.certificate_table.items:
                rows.append(["Type",cert.certificate_type])
                rows.append(["Revision",cert.revision])
                rows.append(["Length",cert.length])
    except AttributeError:
        pass
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def pe_parser_extract(data,args):
    """Extracts sections from a PE file"""
    for section in data.pe.sections:
        if section.name == args or section.name == f".{args}":
            secho(section.body.decode(u"UTF-8", errors="ignore"))

def pe_parser_certificate(data):
    """Extracts a certificate from a PE file"""
    for cert in data.pe.certificate_table.items:
        secho(cert.certificate_bytes)
    
def pe_parser_datadirs(data):
    """Get DataDir information from a PE file"""
    rows = []
    for ddir in ['architecture', 'base_relocation_table', 'bound_import', 'certificate_table', 'clr_runtime_header', 'debug', 'delay_import_descriptor',
            'exception_table', 'export_table', 'global_ptr', 'iat', 'import_table', 'load_config_table', 'resource_table', 'tls_table']:
        rows.append([ddir,getattr(data.pe.optional_hdr.data_dirs,ddir).size,hex(getattr(data.pe.optional_hdr.data_dirs,ddir).virtual_address)])
    t = {"header": ["DataDir","Size","Virtual Address"], "rows": rows}
    return t

def pe_parser_extract_datadir(data,datadir):
    if hasattr(data.pe.optional_hdr.windows,"image_base_64"):
        base = int(data.pe.optional_hdr.windows.image_base_64)
    else:
        base = int(data.pe.optional_hdr.windows.image_base_32)
    content = Deject.r2_handler.cmd("p8 {} @ {}".format(getattr(data.pe.optional_hdr.data_dirs,datadir).size,hex(base+int(getattr(data.pe.optional_hdr.data_dirs,datadir).virtual_address))))
    sshash = ssdeep.hash(binascii.unhexlify(content.strip()))
    filepath = os.path.dirname(Deject.file_path)
    f = open(filepath + "/" + datadir, "wb")
    f.write(binascii.unhexlify(content.strip()))
    f.close()
    secho(f"SSDEEP Hash: {sshash}",fg=colors.GREEN)
    secho(f"[+] Saved output of {datadir} to {filepath}/{datadir}",fg=colors.GREEN)

def pe_parser_sections(data):
    """Extracts section information from a PE file"""
    rows = []
    for section in data.pe.sections:
        rows.append(["Section",section.name])
        rows.append(["Virtual Size",section.virtual_size])
        rows.append(["Raw Data Size",section.size_of_raw_data])
        rows.append(["Virtual Address",hex(section.virtual_address)])
        rows.append(["Section Characteristics (raw)",hex(section.characteristics)])
        rows.append(["Section Characteristics","\n".join(pe_parser_sect_char_lookup(section.characteristics))])
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def pe_parser_pe_char_lookup(data):
    characteristics = []
    for i in [e.value for e in PeCharact]:
        try:
            if data&i > 0:
                characteristics.append(PeCharact(data&i).name)
        except ValueError:
            continue
    return characteristics

def pe_parser_sect_char_lookup(data):
    characteristics = []
    for i in [e.value for e in SectCharact]:
        try:
            if data&i > 0:
                characteristics.append(SectCharact(data&i).name)
        except ValueError:
            continue
    return characteristics

def pe_parser_dll_char_lookup(data):
    characteristics = []
    for i in [e.value for e in DllCharact]:
        try:
            if data&i > 0:
                characteristics.append(DllCharact(data&i).name)
        except ValueError:
            continue
    return characteristics

def help():
    print("""
PE Parser plugin

SYNOPSIS <filename> "[options]"

Uses the PE parser from Kaitai to read information from a PE file.
If extract and a section name is added, extract data from that section (enclose in quotes).
Specifyng "certificate" as an option will extract the certificate, if available in the PE file.
""")
