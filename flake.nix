{
  description = "Memory dump and Sample analysis tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs: let
    inherit (inputs.nixpkgs) lib;

    supportedSystems = ["x86_64-linux"];
    genSystems = lib.genAttrs supportedSystems;

    pkgsFor = system:
      import inputs.nixpkgs {
        inherit system;
        overlays = [(import ./nix/overlays)];
      };
  in {
    packages = genSystems (system: let
      pkgs = pkgsFor system;
    in rec {
      default = pkgs.python311Packages.callPackage ./nix {};
      deject = default;
    });

    devShells = genSystems (system: let
      pkgs = pkgsFor system;
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          python3
          inputs.self.packages.${system}.default
        ];
      };
    });
  };
}
