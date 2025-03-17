# DEJECT - Memory dump and Sample analysis tool

---

## Dependencies
This project has the following dependencies that cannot be installed via Python:
* Poetry - Dependency management for Python (https://python-poetry.org/)
* Radare2/Rizin - Reverse Engineering Framework (https://rada.re/ / https://rizin.re/)
* libfuzzy-dev

Required for M2Crypto:
* libssl-dev
* swig
* python3-dev
* gcc

For the Zeek plugin:
* [Zeek](https://github.com/zeek/zeek)

For the Bulk Extractor plugin:
* [Bulk Extractor](https://github.com/simsong/bulk_extractor)

**NB**: Support for Rizin is still new and has not been fully tested.

## Installation

Clone the repository with GIT using the following command:

`git clone --recurse-submodules https://github.com/WithSecureLabs/deject.git`

In the deject folder run:

`poetry install`

This should install the Python dependencies and create a new virtual environment for Deject.
Run Deject by typing the following command in the Deject directory:
`poetry run deject`

## Building with Nix

This project contains `flake.nix` file, which means that following outputs can be produced:
```
├───devShells
│   └───x86_64-linux
│       └───default: development environment 'nix-shell'
└───packages
    └───x86_64-linux
        ├───default: package 'python3.11-deject-0.4.0'
        └───deject: package 'python3.11-deject-0.4.0'
```

### devShell

`devShell` is, as the name suggest, dev-friendly environment, with all the required dependencies, to build and continue development of this project.
This also creates a 'temporary' shell, with the built package provided, added to that given devShell PATH.

In order to do that, run the following in Deject's root dir:

`nix develop`

> no other information is required, as there's only one devShell associated with this flake

### binary output

If you want to build a binary of this project, using Nix, run the following inside Deject's root dir:

`nix build`

> no other information is required in this case neither, as both outputs for 'packages' are identical, as seen in the output of `nix flake show` above

This will create a directory `result`, and the deject binary will be located under `./result/bin/deject`.

## Tests
To run the tests, to check that Deject is working correct, use the following command in the Deject directory:

`poetry run pytest`

## M2Crypto Install
If the above command fails on the M2Crypto Python package, install the following dependancies:
`libssl-dev swig python3-dev gcc`
(these are the package names for Debian, if using RedHat names might be different.)

## Zeek Install
Install Zeek from via a package manager (https://docs.zeek.org/en/master/install.html) or from source (https://github.com/zeek/zeek).
Run `ln -s /path/to/zeek bin/zeek` to link the Zeek binary in the `bin` directory for the Zeek plugin to find it.
This is only needed if you want to run the Zeek plugin to analyse pcap files.

## Basic Usage

To list the available plugins: `poetry run deject plugins`

In the deject folder run `poetry run deject run <path to memory dump>`

To run only a single plugin use the `--include <plugin name>` option.

Some plugins require an argument, place this after the memory dump, such as:

`--include pe_hashes <path to memory dump> <base_addr>`

To provide an argument starting with a `-` or more than one argument to the application, use quotes:
* `--include cobaltstrike_check <path to memory dump> " -J "`
* `--include pe_sections <path to exe> "carve .text"`

## Dockerfile
To provide a unified environment a Dockerfile is provided.

Buildx is the suggested client, install buildx from https://docs.docker.com/build/install-buildx/ (documentation: https://github.com/docker/buildx#linux-packages). (On Debian run `apt-get install docker-buildx-plugin`)
Running `docker buildx install` makes Buildx the default build client (this only needs to be done once.)

```
docker buildx install
docker build --tag deject .
cd dir/with/malware
docker run -v "$PWD":/work --tty deject --include pdf_object /work/<file> <object>
```

## Malware Samples
If you want to test Deject but don't have any malware, you can download malware samples from:
https://github.com/jstrosch/malware-samples
Beware that these are live samples, use at your own risk.

## Generating Documentation
Documentation can be generated using Doxygen (https://github.com/doxygen/doxygen) by using the following command:
```
doxygen deject-docs
```
This will output HTML pages to the `docs/` directory.

## Settings

### VTKEY
For plugins that require a VirusTotal API key, set a `VT_KEY` environment variable:
```
set VT_KEY=<vtapi>
```

### Yara Rules
The default Yara rule repository is located at `scripts/yara-rules`. To use a different set of Yara rules, set the `RULES` environment variable:
```
set RULES=<path/to/yara/rules>
```

### Zeek
The default location for Zeek is the `bin/` directory. This can be changed using the `ZEEK_PATH` environment variable:
```
set ZEEK_PATH=</path/to/zeek>`
```
You will need to install Zeek separately.

### Bulk Extractor
The default location for Bulk Extractor is the `bin/` directory. This can be changed using the `BULK_PATH` environment variable:
```
set BULK_PATH=</path/to/bulk_extractor>
```
You will need to install Bulk Extractor separately.

## Useful Links

* https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta
* https://github.com/jstrosch/malware-samples

## Acknowledgements
* [Didier StevenS](https://github.com/DidierStevens/DidierStevensSuite) (1768.py and pdftool/pdfid/pdf-parser)
* [Chepy](https://github.com/securisec/chepy)
* [mwcfg-modules](https://github.com/c3rb3ru5d3d53c/mwcfg-modules/tree/master)
* [Malduck](https://github.com/CERT-Polska/malduck)
* [Radare2](https://github.com/radareorg/radare2)/[Rizin](https://github.com/rizinorg/rizin)
* [Yara](https://github.com/virustotal/yara)
* [KaitaiStruct](https://github.com/kaitai-io/kaitai_struct)
* [Protections Artifacts](https://github.com/elastic/protections-artifacts) (Elastic)
* [pefile](https://github.com/erocarrera/pefile)
* [dc3-mwcp](https://github.com/dod-cyber-crime-center/DC3-MWCP)
* [minidump](https://github.com/skelsec/minidump/)
