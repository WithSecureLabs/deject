"""!
@brief uses Kaitai (https://github.com/kaitai-io/kaitai_struct_compiler) to parse MDMP files.
@details Can supply "sysinfo", "processdata", "misc" to get information out of the MDMP.
By default runs sysinfo.
Note: uses match/case in Python, needs Python 3.10 minimum.
"""
from deject.plugins import Deject
from scripts.extractors.kaitai.windows_minidump import WindowsMinidump
from datetime import datetime, timezone
from enum import Flag


class Flags1(Flag):
    MINIDUMP_MISC1_PROCESS_ID = 0x1
    MINIDUMP_MISC1_PROCESS_TIMES = 0x2
    MINIDUMP_MISC1_PROCESSOR_POWER_INFO = 0x4
    MINIDUMP_MISC3_PROCESS_INTEGRITY = 0x10
    MINIDUMP_MISC3_PROCESS_EXECUTE_FLAGS = 0x20
    MINIDUMP_MISC3_TIMEZONE = 0x40
    MINIDUMP_MISC3_PROTECTED_PROCESS = 0x80
    MINIDUMP_MISC4_BUILDSTRING = 0x100
    MINIDUMP_MISC5_PROCESS_COOKIE = 0x200


class Flags(Flag):
    MiniDumpNormal = 0x0
    MiniDumpWithDataSegs = 0x1
    MiniDumpWithFullMemory = 0x2
    MiniDumpWithHandleData = 0x4
    MiniDumpFilterMemory = 0x8
    MiniDumpScanMemory = 0x10
    MiniDumpWithUnloadedModules = 0x20
    MiniDumpWithIndirectlyReferencedMemory = 0x40
    MiniDumpFilterModulePaths = 0x80
    MiniDumpWithProcessThreadData = 0x100
    MiniDumpWithPrivateReadWriteMemory = 0x200
    MiniDumpWithoutOptionalData = 0x400
    MiniDumpWithFullMemoryInfo = 0x800
    MiniDumpWithThreadInfo = 0x1000
    MiniDumpWithCodeSegs = 0x2000
    MiniDumpWithoutAuxiliaryState = 0x4000
    MiniDumpWithFullAuxiliaryState = 0x8000
    MiniDumpWithPrivateWriteCopyMemory = 0x10000
    MiniDumpIgnoreInaccessibleMemory = 0x20000
    MiniDumpWithTokenInformation = 0x40000
    MiniDumpWithModuleHeaders = 0x80000
    MiniDumpFilterTriage = 0x100000
    MiniDumpWithAvxXStateContext = 0x200000
    MiniDumpWithIptTrace = 0x400000
    MiniDumpScanInaccessiblePartialPages = 0x800000
    MiniDumpFilterWriteCombinedMemory = 0x1ffffff
    MiniDumpValidTypeFlags = 0x1ffffff


@Deject.plugin
def minidump_parser():
    """This function allows for parsing MDMP files."""
    data = WindowsMinidump.from_file(Deject.file_path)
    match Deject.plugin_args:
        case "sysinfo":
            result = minidump_parser_sysinfo(data)
        case "processdata":
            result = minidump_parser_process_data(data)
        case "modulelist":
            result = minidump_parser_module_list(data)
        case "memoryinfo":
            result = minidump_parser_memory_info(data)
        case "token":
            result = minidump_parser_token(data)
        case "functiontable":
            result = minidump_parser_function_table(data)
        case "threadnames":
            result = minidump_parser_thread_names(data)
        case "handledata":
            result = minidump_parser_handle_data(data)
        case "threadlist":
            result = minidump_parser_thread_list(data)
        case "mem64":
            result = minidump_parser_mem64(data)
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
            rows.append(["Architecture", stream.data.cpu_arch])
            rows.append(["OS Version", stream.data.os_ver_major])
            rows.append(["OS Platform", stream.data.os_platform])
            rows.append(["OS Build", stream.data.os_build])
            rows.append(["OS Reserved", stream.data.reserved2])
            rows.append(["OS Type", stream.data.os_type])
            rows.append(["Number of CPUs", stream.data.num_cpus])

    t = {"header": ["Key", "Value"], "rows": rows}
    return t


def minidump_parser_process_data(data):
    """This function is used to parse process data from a minidump file"""
    memRanges = []
    replacements = [b"\x00", b"\x0f", b"\x1e", b"\x7f", b"\x10"]
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.memory_list":
            for memoryRange in stream.data.mem_ranges:
                memRanges.append(memoryRange.addr_memory_range)
                processMemoryData = memoryRange.memory.data
                processMemoryDataDecoded = processMemoryData.decode(
                    u"UTF-16-LE", errors="replace",
                )
                processMemoryDataLength = memoryRange.memory.len_data
                for i in replacements:
                    rep = i.decode(u"UTF-16-LE", errors="replace")
                    processMemoryDataDecoded.replace(rep, '').replace('\n', '')
                if '.exe' in processMemoryDataDecoded or '.dll' in processMemoryDataDecoded:
                    return f"Memory Range: {memoryRange}\n" + \
                        f"Length:{processMemoryDataLength}\n" + \
                        f"Process Data: {processMemoryDataDecoded.strip()}"


def minidump_parser_module_list(data):
    """This function is used to parse the module list data from a minidump file"""
    for stream in data.streams:
        replacements = [b"\x00", b"\x0f", b"\x1e", b"\x7f", b"\x10"]
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.module_list":
            moduleListDecoded = stream.data.decode("utf-8", errors="ignore")
            for i in replacements:
                rep = i.decode(u"UTF-16-LE", errors="replace")
                moduleListDecoded.replace(rep, '').replace('\n', '')
            return f"Process Module list: {moduleListDecoded.strip()}"


def minidump_parser_token(data):
    """This function is used to parse the token data from a minidump file"""
    for stream in data.streams:
        replacements = [b"\x00", b"\x0f", b"\x1e", b"\x7f", b"\x10"]
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.token":
            tokenDecoded = stream.data.decode("utf-8", errors="ignore")
            for i in replacements:
                rep = i.decode(u"UTF-16-LE", errors="replace")
                tokenDecoded.replace(rep, '').replace('\n', '')
            return f"Token: {tokenDecoded.strip()}"


def minidump_parser_function_table(data):
    """This function is used to parse the function table data from a minidump file"""
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        replacements = [b"\x00", b"\x0f", b"\x1e", b"\x7f", b"\x10"]
        if streamTypeStr == "StreamTypes.function_table":
            functionTableDecoded = stream.data.decode("utf-8", errors="ignore")
            for i in replacements:
                rep = i.decode("utf-8", errors="ignore")
                functionTableDecoded.replace(rep, '').replace('\n', '')
            return f"Process Function table: {functionTableDecoded[0].strip()}"


def minidump_parser_thread_names(data):
    """This function is used to parse thread data from a minidump file"""
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.thread_names":
            threadNamesDecoded = stream.data.decode("utf-8", errors="ignore")
            return f"Thread Names: {threadNamesDecoded}"


def minidump_parser_handle_data(data):
    """This function is used to parse handle data from a minidump file"""
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.handle_data":
            handleDataDecoded = stream.data.decode("utf-8", errors="ignore")
            return f"Process Handle Data: {handleDataDecoded}"


def minidump_parser_thread_list(data):
    """This function is used to parse thread list data from a minidump file"""
    replacements = [b"\x00", b"\x0f", b"\x1e", b"\x7f", b"\x10"]
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.thread_list":
            for thread in stream.data.threads:
                threadMemoryDataDecoded = thread.stack.memory.data.decode(
                    "utf-8", errors="ignore",
                )
                for i in replacements:
                    rep = i.decode("utf-8", errors="ignore")
                    threadMemoryDataDecoded.replace(rep, '').replace('\n', '')
                return f"Total Threads: {stream.data.num_threads}\n" + \
                    f"Thread Environment Block(TEB): {thread.teb} \n" + \
                    f"Thread ID: {thread.thread_id} \n" + \
                    f"Suspended: {thread.suspend_count} \n" + \
                    f"Thread memory range: {thread.stack.addr_memory_range} \n" + \
                    f"Data length (Bytes): {thread.stack.memory.len_data} \n" + \
                    f"Data (Decoded): {threadMemoryDataDecoded.strip()} \n"


def minidump_parser_mem64(data):
    """This function is used to parse mem64 data from a minidump file"""
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.memory_64_list":
            return f"Memory x64 list (raw): {stream.data}\n"


def minidump_parser_misc(data):
    """This function is used to parse misc_info from a minidump file"""
    rows = []
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.misc_info":
            rows.append([
                "Process Dump Creation Time", datetime.fromtimestamp(
                    data.timestamp, timezone.utc,
                ).strftime("%Y-%m-%d %H:%M:%S"),
            ])
            rows.append(["Checksum", data.checksum])
            creationtime = datetime.fromtimestamp(
                stream.data.process_create_time, timezone.utc,
            ).strftime("%Y-%m-%d %H:%M:%S")
            rows.append(["Process ID", stream.data.process_id])
            rows.append(["Process Creation Time", creationtime])
            rows.append([
                "Process Kernel Time", datetime.fromtimestamp(
                    stream.data.process_kernel_time, timezone.utc,
                ).strftime("%H:%M:%S"),
            ])
            rows.append([
                "Process User Time", datetime.fromtimestamp(
                    stream.data.process_user_time, timezone.utc,
                ).strftime("%H:%M:%S"),
            ])
            rows.append(["Flags1 (raw)", hex(stream.data.flags1)])
            rows.append([
                "Flags1", "\n".join(
                    minidump_parser_flags1_lookup(stream.data.flags1),
                ),
            ])
            rows.append(["Flags (raw)", hex(data.flags)])
            rows.append(
                ["Flags", "\n".join(minidump_parser_flags_lookup(data.flags))],
            )
    t = {"header": ["Key", "Value"], "rows": rows}
    return t


def minidump_parser_memory_info(data):
    for stream in data.streams:
        streamTypeStr = str(stream.stream_type)
        if streamTypeStr == "StreamTypes.memory_info_list":
            return f"Memory info list (raw): {stream.data}\n"


def minidump_parser_flags1_lookup(data):
    """This function is used to lookup the Flags1 enum values"""
    flags1 = []
    for i in [e.value for e in Flags1]:
        try:
            if data & i > 0:
                flags1.append(Flags1(data & i).name)
        except ValueError:
            continue
    return [flag1 for flag1 in flags1 if flag1 is not None]


def minidump_parser_flags_lookup(data):
    """This function is used to lookup the Flags enum values"""
    flags = []
    for i in [e.value for e in Flags]:
        try:
            if data & i > 0:
                flags.append(Flags(data & i).name)
        except ValueError:
            continue
    return [flag for flag in flags if flag is not None]


def help():
    print("""
Minidump Parser Plugin
SYNOPSIS <filename> [sysinfo|processdata|misc]
Parses a MDMP file using Kaitai and returns Streams from the memory dump.
""")
