"""!
@brief Get Digital Signatures from a PE file and display using OpenSSL.
"""
from deject.plugins import Deject
import binascii
from scripts.helpers import helpers
import tempfile


@Deject.plugin
def pe_signatures():
    """Get digital signatures out of PE files"""
    filename = Deject.file_path
    info = Deject.r2_handler.cmdj("ij")
    bits = info["bin"]["bits"]
    Deject.r2_handler.cmd(f"on {filename}")
    if bits == 64:
        size = Deject.r2_handler.cmd(
            "pfv.pe_nt_image_headers64.optionalHeader.dataDirectory[4].size @ pe_nt_image_headers64",
        )
        virtualaddress = Deject.r2_handler.cmd(
            "pfv.pe_nt_image_headers64.optionalHeader.dataDirectory[4].virtualAddress @ pe_nt_image_headers64",
        )
    else:
        size = Deject.r2_handler.cmd(
            "pfv.pe_nt_image_headers32.optionalHeader.dataDirectory[4].size @ pe_nt_image_headers32",
        )
        virtualaddress = Deject.r2_handler.cmd(
            "pfv.pe_nt_image_headers32.optionalHeader.dataDirectory[4].virtualAddress @ pe_nt_image_headers32",
        )
    output = Deject.r2_handler.cmd(
        f"p8 {size.strip()} @ {virtualaddress.strip()}+8",
    )
    with tempfile.NamedTemporaryFile(mode="wb") as cert:
        cert.write(binascii.unhexlify(output.strip()))
        helpers.bin_exec(
            helpers, [
                "openssl", "pkcs7", "-inform", "DER", "-print_certs", "-text", "-in", cert.name,
            ],
        )
    Deject.r2_handler.cmd(f"o {filename}")


def help():
    print("""
PE Signatures plugin
SYNOPSIS <filename>
Extracts digital signatures from a PE file and uses OpenSSL to display them.
""")
