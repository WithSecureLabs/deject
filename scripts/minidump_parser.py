"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse MDMP files.
@details Can supply "sysinfo", "processdata", "misc" to get information out of the MDMP.
By default runs sysinfo.
Note: uses match/case in Python, needs Python 3.10 minimum.
"""
from deject.plugins import Deject
from scripts.extractors.kaitai.windows_minidump import WindowsMinidump
from datetime import datetime
from typer import secho,colors

@Deject.plugin
def minidump_parser():
    """This function allows for parsing MDMP files."""
    data = WindowsMinidump.from_file(Deject.file_path)
    match Deject.plugin_args:
        case "sysinfo":
            result = minidump_parser_sysinfo(data)
        case "processdata":
            result = minidump_parser_process_data(data)
        case "misc":
            result = minidump_parser_misc(data)
        case _:
            result = minidump_parser_sysinfo(data)
    return result


def minidump_parser_sysinfo(data):
    """This function is used to parse information from a minidump file"""
    rows = []
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.system_info":
                rows.append(["OS Version",stream.data.os_ver_major])
                rows.append(["OS Platform",stream.data.os_platform])
                rows.append(["OS Build:",stream.data.os_build])
                rows.append(["OS Reserved", stream.data.reserved2])
                rows.append(["OS Type:",stream.data.os_type])

    t = {"header": ["Key","Value"], "rows": rows}
    return t

def minidump_parser_process_data(data):
    """This function is used to parse process data from a minidump file"""
    memRanges = []
    replacements = [b"\x00",b"\x0f",b"\x1e",b"\x7f",b"\x10"]
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.memory_list":
            pMemoryRanges = stream.data.mem_ranges
            secho("[+] Process Information...", fg=colors.GREEN)
            for memoryRange in pMemoryRanges:
                processMemoryRange = memoryRange.addr_memory_range
                if processMemoryRange not in memRanges:
                    memRanges.append(processMemoryRange)
                    processMemoryData = memoryRange.memory.data
                    processMemoryDataDecoded = processMemoryData.decode(u"UTF-16-LE",errors="replace")
                    processMemoryDataLength = memoryRange.memory.len_data
                    for i in replacements:
                        rep = i.decode(u"UTF-16-LE",errors="replace")
                        processMemoryDataDecoded.replace(rep,'').replace('\n','')
                    if  '.exe' in processMemoryDataDecoded or '.dll' in processMemoryDataDecoded:
                        secho(f"Memory Range: {processMemoryRange}", fg=colors.GREEN)
                        secho(f"Length:{processMemoryDataLength}", fg=colors.GREEN)
                        secho(f"Process Data: {processMemoryDataDecoded.strip()}", fg=colors.GREEN)

def minidump_parser_misc(data):
    """This function is used to parse misc_info from a minidump file"""
    rows = []
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.misc_info":
            pCreationTime = datetime.fromtimestamp(stream.data.process_create_time)
            rows.append(["Process ID:",stream.data.process_id])
            rows.append(["Process Creation Time:", pCreationTime])    
    t = {"header": ["Key","Value"], "rows": rows}
    return t

def help():
    print("""
Minidump Parser Plugin
SYNOPSIS <filename> [sysinfo|processdata|misc]
Parses a MDMP file using Kaitai and returns Streams from the memory dump.
""")
