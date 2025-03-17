final: prev: {
  pythonPackagesExtensions =
    prev.pythonPackagesExtensions
    ++ [
      (
        python-final: python-prev: let
          c = python-final.callPackage;
        in {
          chepy = c ./chepy {};
          dotnetfile = c ./dotnetfile {};
          mwcp = c ./mwcp {};
          netstruct = c ./netstruct {};
          libmagic = c ./libmagic {};

          minidump = python-prev.minidump.overrideAttrs (self: super: {
            src = final.fetchurl {
              url = "https://files.pythonhosted.org/packages/26/4b/bc695b99dc7d77d28223765c3ee5a31d34fd2850c52eb683ccdd1206067d/minidump-0.0.24.tar.gz";
              hash = "sha256-964JuUTzsXzPXOzGb5/1p6RbBTR0oTrrAS9MkgRHBDc=";
            };
          });
        }
      )
    ];
}
