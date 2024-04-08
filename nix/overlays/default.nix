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
              url = "https://files.pythonhosted.org/packages/47/88/6d085c3976f179fb90dbab30ed56c72df901ceb727d4b99bf858dba5f089/minidump-0.0.21.tar.gz";
              hash = "sha256-g9YSr7bFdyfr84rKQztVD4P5+MfDtlYq0quXBx/YXzo=";
            };
          });
        }
      )
    ];
}
