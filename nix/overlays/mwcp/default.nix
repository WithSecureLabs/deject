{
  lib,
  fetchurl,
  buildPythonPackage,
  poetry-core,
}:
buildPythonPackage {
  pname = "mwcp";
  version = "3.13.1";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/fa/78/4924c25f40b92854800da8e3d94d10da8a78ca46e7ea0b013effd48b7209/mwcp-3.13.1.tar.gz";
    hash = "sha256-Muh97OddtZgBtXkuudLJZ9wGEL76M6S/kJ4FHE5yxBs=";
  };

  doCheck = false;

  nativeBuildInputs = [
    poetry-core
  ];

  meta = with lib; {
    description = "DC3 Malware Configuration Parser";
    homepage = "https://github.com/dod-cyber-crime-center/DC3-MWCP";
    license = licenses.mit;
  };
}
