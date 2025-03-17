"""!
@brief Search hashes on CIRCL hashlookup.
@details CIRCL hashlookup (https://circl.lu/services/hashlookup/) is used to check if a hash is known
in a database.
"""
from deject.plugins import Deject
import requests
import hashlib

# TODO: Do we want to keep requests or to change to the offline Bloom filter?
# This could also be an option, with "offline" being an argument.


@Deject.plugin
def hashlookup():
    """Use hashlookup.circl.lu to check if the sha1 hash of a file is known"""
    with open(Deject.file_path, "rb") as f:
        data = f.read()
    filehash = hashlib.sha1(data).hexdigest()
    r = requests.get(f'https://hashlookup.circl.lu/lookup/sha1/{filehash}')
    if r.status_code == 200:
        return f"{r.json()}"
    elif r.status_code == 404:
        return "Hash not found!"
    else:
        return "Hash format incorrect, this might be a bug."


def help():
    print("""
Hashlookup plugin
SYNOPSIS <filename>

This plugin uses hashlookup.circl.lu to lookup a SHA1 hash of the file passed to Deject.
There are no additional arguments for this plugin.
""")
