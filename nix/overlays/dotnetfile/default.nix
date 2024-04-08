{
  lib,
  fetchFromGitHub,
  buildPythonPackage,
  poetry-core,
  pefile
}:
buildPythonPackage rec {
  pname = "dotnetfile";
  version = "0.2.4";

  src = fetchFromGitHub {
    owner = "pan-unit42";
    repo = "dotnetfile";
    rev = "v${version}";
    hash = "sha256-+MfxJeN/IOI6Ev8kgzFVSzESXi8TcUkrCF4f0kBHMqk=";
  };

  doCheck = false;

  nativeBuildInputs = [
    poetry-core
  ];

  propagatedBuildInputs = [
    pefile
  ];

  meta = with lib; {
    description = "Portable Executable reader module";
    homepage = "Portable Executable reader module";
    license = licenses.mit;
  };
}
