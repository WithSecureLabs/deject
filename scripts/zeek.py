"""!
@brief Run Zeek over a PCAP file to extract information
@details Zeek output is placed in the same location as the pcap file.
Arguments can be passed to the Zeek binary by placing them after the file
name, in quotes. For example,
poetry run deject run --include zeek test.pcap " -C " will run zeek with checksums
turned off.
Download Zeek and link or copy the binary to bin/ in Deject's root directory.
"""
from deject.plugins import Deject
import os
from scripts.helpers import helpers, Settings


@Deject.plugin
def zeek():
    """Use zeek on a PCAP."""
    filename = Deject.file_path
    filepath = os.path.dirname(Deject.file_path)
    zeek = f"{os.path.dirname(os.path.realpath(__file__))}/../bin/zeek"
    if not os.path.exists(zeek):
        if Settings().getSetting("zeek_path"):
            zeek = Settings().getSetting("zeek_path")
        else:
            zeek = "zeek"
    process = [zeek, "-r", filename, f"Log::default_logdir={filepath}"]
    args = Deject.plugin_args
    if args == "False":
        helpers.bin_exec(helpers, process)
    else:
        helpers.bin_exec(helpers, process + args.strip().split(" "))
    return f"[+] Zeek output for {filename} has been saved to {filepath}"


def help():
    print("""
Zeek plugin
SYNOPSIS <file> [arguments]
Arguments are passed to the Zeek binary.

To run the help for the Zeek binary, run poetry run deject run --include zeek test.pcap " --help ".

Zeek output is placed in the same location as the pcap file.
Arguments can be passed to the Zeek binary by placing them after the file
name, in quotes. For example,
poetry run deject run --include zeek test.pcap " -C " will run zeek with checksums
turned off.
Download Zeek and link or copy the binary to bin/ in Deject's root directory.
""")
