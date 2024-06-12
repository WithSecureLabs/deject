{
  lib,
  fetchurl,
  buildPythonPackage,
  poetry-core,
}:
buildPythonPackage {
  pname = "libmagic";
  version = "1.0";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/83/86/419ddfc3879b4565a60e0c75b6d19baec48428cbc2f15aca5320b3d136f6/libmagic-1.0.tar.gz";
    hash = "sha256-ZJ8c5/t8knlrrbuBJVXkqSY1HaT1zfgugQtc03Gu340=";
  };

  doCheck = false;

  nativeBuildInputs = [
    poetry-core
  ];

  meta = with lib; {
    description = "libmagic bindings using FFL (ctypes)";
    homepage = "https://bitbucket.org/xmonader/pymagic-dev";
    license = licenses.gpl3Plus;
  };
}
