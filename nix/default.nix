{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  poetry-core,
  radare2,
  ssdeep,
  openssl,
  util-linux,
  file,
  # python
  exceptiongroup,
  hexdump,
  kaitaistruct,
  malduck,
  minidump,
  pdf2image,
  pefile,
  pycryptodome,
  python-magic,
  r2pipe,
  requests,
  rzpipe,
  tabulate,
  telfhash,
  typer,
  yara-python,
  oletools,
  olefile,
  # from overlay
  chepy,
  dotnetfile,
  netstruct,
  libmagic,
  mwcp,
  pyyaml,
}: let
  yara-rules = fetchFromGitHub {
    owner = "elastic";
    repo = "protections-artifacts";
    rev = "cb45629514acefc68a9d08111b3a76bc90e52238";
    hash = "sha256-ZKpnNgFlS6L9jzjB7lz8WL3poqd25hW2g5cZ3lJZTcI=";
  };

  relayRumbler = fetchFromGitHub {
    owner = "ajpc500";
    repo = "RelayRumbler";
    rev = "57b70f50ad305c73efc91acbba418c361ebc665b";
    hash = "sha256-ntV4sEFruUtZYu+rtwROm2kJunDSmeW26DHk9qmQyy0=";
  };

  malware-config-extractor = fetchFromGitHub {
    owner = "c3rb3ru5d3d53c";
    repo = "mwcfg-modules";
    rev = "3f7702d1d5896bb14d8cbb401a5f155002f6698a";
    hash = "sha256-fSPyFOz0QDZdSSZDMuzzRfjPcHOKJJRsOjQHS6+rMuI=";
  };
in
  buildPythonPackage {
    pname = "deject";
    version = "0.5.0";

    format = "pyproject";

    src = ../.;

    preConfigure = ''
      substituteInPlace pyproject.toml \
        --replace 'ipaddress = "^1.0.23"' ""
    '';

    nativeBuildInputs = [
      poetry-core
    ];

    propagatedBuildInputs = [
      openssl.dev
      radare2
      ssdeep
      util-linux
      file

      exceptiongroup
      hexdump
      kaitaistruct
      malduck
      minidump
      pdf2image
      pefile
      pycryptodome
      python-magic
      r2pipe
      requests
      rzpipe
      tabulate
      telfhash
      typer
      yara-python
      pyyaml

      chepy
      dotnetfile
      netstruct
      libmagic
      mwcp
      olefile
      oletools
    ];

    postInstall = let
      scripts = "$out/lib/python3.11/site-packages/scripts";
    in ''
      mkdir ${scripts}
      cp -r scripts/{extractors,pdf-tools} ${scripts}/
      cp -r ${yara-rules} ${scripts}/yara-rules

      cp -r ${malware-config-extractor} ${scripts}/extractors/MalwareConfigExtractor
      cp -r ${relayRumbler} ${scripts}/extractors/RelayRumbler
    '';

    meta = with lib; {
      description = "Memory dump and Sample analysis tool";
      homepage = "https://github.com/WithSecureLabs/deject";
      license = licenses.gpl3Plus;
    };
  }
