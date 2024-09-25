{
  lib,
  fetchurl,
  buildPythonPackage,
  poetry-core,
}:
buildPythonPackage {
  pname = "chepy";
  version = "7.2.0";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/cb/34/64261d7284e8e488bedad78e34f4ccaa95c990ddb8c2890e5363a41ba237/chepy-7.2.0.tar.gz";
    hash = "sha256-f/mvLyO+fm7ge5gCBuJpbfC+TDSCuSbTuvevHqC+Bbg=";
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
