{
  description = "Hephaestus: authoritative Jujutsu (jj) storage, GRNB0002 Zstd CAS, Decision/Observation logs, and pure-IPv6 Ed25519 mTLS QUIC server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (system: pkgs: {
        hephaestus-server = pkgs.rustPlatform.buildRustPackage {
          pname = "hephaestus-server";
          version = "0.1.0-alpha.1";
          src = self;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          cargoBuildFlags = [ "-p" "hephaestus-server" "--bin" "hephaestus-server" ];
          cargoTestFlags = [ "-p" "hephaestus-core" "-p" "hephaestus-store" "-p" "hephaestus-store-sqlite" ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            sqlite
            zstd
          ];

          meta = with pkgs.lib; {
            description = "Authoritative Jujutsu (jj) storage backend and IPv6 Ed25519 mTLS QUIC server";
            homepage = "https://github.com/kmosoti/Hephaestus";
            license = licenses.asl20;
            mainProgram = "hephaestus-server";
            platforms = platforms.linux;
          };
        };

        default = self.packages.${system}.hephaestus-server;
      });

      nixosModules = {
        hephaestus = import ./nix/modules/hephaestus.nix;
        default = self.nixosModules.hephaestus;
      };

      devShells = forAllSystems (_system: pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            binutils
            cargo
            clippy
            git
            jq
            jujutsu
            pkg-config
            ripgrep
            rustc
            rustfmt
            sqlite
            zstd
          ];
        };
      });
    };
}
