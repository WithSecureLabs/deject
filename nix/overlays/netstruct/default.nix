{
  lib,
  fetchurl,
  buildPythonPackage,
  poetry-core,
}:
buildPythonPackage {
  pname = "netstruct";
  version = "1.1.2";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/b8/eb/460b09c71d65ea3ea7ff89271207935c44e30aa558b64f5102441f129191/netstruct-1.1.2.zip";
    hash = "sha256-cLalxz9bvHq1ewGTaWQq37NN2K9BuUjEAM6V+VK335o=";
  };

  doCheck = false;

  nativeBuildInputs = [
    poetry-core
  ];

  meta = with lib; {
    description = "struct-like module for Python designed to make it a bit easier to send and received packed binary data";
    homepage = "https://github.com/stendec/netstruct";
    license = licenses.asl20;
  };
}
