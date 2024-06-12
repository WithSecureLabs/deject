{
  lib,
  fetchurl,
  buildPythonPackage,
  poetry-core,
}:
buildPythonPackage {
  pname = "chepy";
  version = "6.5.0";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/fb/11/2710f6b1ee502126546b93ebfc6774aae09402c3ce810268c9d780d9673e/chepy-6.5.0.tar.gz";
    hash = "sha256-v7JxnpH9zi3lFu1bbIeUrsCL984ybpv6tqMQsMKyXPU=";
  };

  doCheck = false;

  nativeBuildInputs = [
    poetry-core
  ];

  meta = with lib; {
    description = "Chepy is a python lib/cli equivalent of the awesome CyberChef tool";
    homepage = "https://github.com/securesec/chepy";
    license = licenses.gpl3Plus;
  };
}
