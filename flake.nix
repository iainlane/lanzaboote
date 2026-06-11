{
  description = "Secure Boot for NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs-measured-boot.url = "github:iainlane/nixpkgs/measured-boot";

    # Not used in the flake itself. Only used to make the source available for
    # the project.
    pre-commit = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane = {
      url = "github:ipetkov/crane";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-measured-boot,
      crane,
      rust-overlay,
      ...
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        # Not tested in CI. Best effort support.
        "aarch64-linux"
      ];

      # Instantiate only once for each system.
      #
      # Still allow flakes users to override dependencies in the normal flake
      # way.
      lanzaboote = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        import ./. {
          inherit system pkgs rust-overlay;
          crane = crane.mkLib pkgs;
        }
      );

      lanzabooteMeasuredBoot = eachSystem (
        system:
        let
          pkgs = nixpkgs-measured-boot.legacyPackages.${system};
        in
        import ./. {
          inherit system pkgs rust-overlay;
          useMeasuredBootTpm2Module = false;
          crane = crane.mkLib pkgs;
        }
      );
    in
    {
      nixosModules = {
        default = self.nixosModules.lanzaboote;
        lanzaboote = (
          { pkgs, lib, ... }:
          {
            imports = [
              ./nix/modules/lanzaboote.nix
            ];

            boot.lanzaboote.package =
              let
                system = pkgs.stdenv.hostPlatform.system;
              in
              lib.mkDefault self.packages.${system}.lzbt;
          }
        );
      };

      packages = eachSystem (
        system: builtins.removeAttrs lanzaboote.${system}.packages [ "recurseForDerivations" ]
      );

      # Temporarily include the checks in the flake so that CI picks them up.
      checks = eachSystem (
        system:
        let
          checks = lanzaboote.${system}.checks;
          measuredBootChecks = lanzabooteMeasuredBoot.${system}.checks;
        in
        {
          tool = checks.lzbt.package;
          toolClippy = checks.lzbt.clippy;
          toolRustfmt = checks.lzbt.rustfmt;

          shared = checks.shared.package;
          sharedClippy = checks.shared.clippy;
          sharedRustfmt = checks.shared.rustfmt;

          stub = checks.stub.package;
          stubClippy = checks.stub.clippy;
          stubRustfmt = checks.stub.rustfmt;

          docsHtml = checks.docs.html;
          docsOptions = checks.docs.options;

          inherit (checks) pre-commit;
        }
        // builtins.removeAttrs checks.tests [
          "recurseForDerivations"
          "luks-tpm2-autoenroll"
          "luks-tpm2-combined"
          "pcrlock"
          "pcrlock-rollforward"
        ]
        // {
          inherit (measuredBootChecks.tests)
            luks-tpm2-autoenroll
            luks-tpm2-combined
            pcrlock
            pcrlock-rollforward
            ;
        }
      );

    };
}
