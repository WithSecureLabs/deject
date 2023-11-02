from chepy import Chepy
import sys
import os
import argparse
import r2pipe
import rzpipe

def parsePosh(filepath):
    try:
        r = r2pipe.open(filepath, flags=["-2"])
    except:
        r = rzpipe.open(filepath, flags=["-2"])
    strings = r.cmdj("izzj")
    payload = ""
    f = open(filepath, "rb").read()
    if f.startswith(b"MZ"):
        for hit in range(len(strings)):
            if strings[hit]["size"] == 4088 and strings[hit]["type"] == "utf16le":
                payload = payload + strings[hit]["string"]
                hit = hit + 1
    else:
        for hit in range(len(strings)):
            payload = payload + strings[hit]["string"]
            hit = hit + 1
    try:
        output = (
            Chepy(payload)
            .remove_nullbytes()
            .regex_search(r"[a-zA-Z0-9+=]{200,}")
            .from_base64()
            .remove_nullbytes()
            .decode("Latin-1")
            .regex_search(r"[a-zA-Z0-9/\\+=]{100,}")
            .from_base64()
            .gzip_decompress()
            .o
            .decode()
        )
        if len(output):
            print(output)
        else:
            print("Could not extract the configuration.")
    except AttributeError as e:
        print(f"{str(e)}")
    except Exception as e:
        print(f"File might not be PoshC2. {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract PoshC2 configuration"
    )
    parser.add_argument(
        "--file", "-f", required=True, help="Path to suspected PoshC2 sample"
    )
    args = parser.parse_args()
    if not os.path.exists(args.file):
        print(f"[!] Input file does not exist: {args.file}")
        sys.exit(1)

    parsePosh(args.file)
