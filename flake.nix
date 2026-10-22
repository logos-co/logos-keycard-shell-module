{
  description = "Logos Keycard Shell signer: the Shell's accounts, and requests signed on its own screen. Holds no secret.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # logos.wallets/1 (wallets.lidl): the signer manager, bound at runtime, since it depends on
    # this module and this module can't depend on it.
    logos-signer-interface = {
      url = "github:logos-co/logos-signer-interface/ca091a9330d455a5b60b80537e34dc535d1e6503";
      flake = false;
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      lib = nixpkgs.lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross target the builder understands, never a host.
      targets = systems ++ [ "x86_64-windows" ];

      # A Shell in software for the doctests: the crate's own emulator, staged beside the SDK
      # source its manifest names, built without the module.
      emulator = system:
        let
          pkgs = import nixpkgs { inherit system; };
          src = pkgs.runCommand "keycard-shell-emulator-src" { } ''
            mkdir -p $out
            cp -r ${./rust-lib} $out/rust-lib
            cp -r ${logos-module-builder.packages.${system}.rust-sdk-src} $out/logos-rust-sdk-src
          '';
        in
        pkgs.rustPlatform.buildRustPackage {
          pname = "keycard-shell-emulator";
          version = "0.1.0";
          inherit src;
          sourceRoot = "keycard-shell-emulator-src/rust-lib";
          cargoLock = {
            lockFile = ./rust-lib/Cargo.lock;
            allowBuiltinFetchGit = true;
          };
          buildNoDefaultFeatures = true;
          buildFeatures = [ "emulator" ];
          cargoBuildFlags = [ "--bin" "keycard-shell-emulator" ];
          doCheck = false;
          meta.mainProgram = "keycard-shell-emulator";
        };
    in
    {
      packages = lib.genAttrs targets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system}
        // lib.optionalAttrs (builtins.elem system systems) { emulator = emulator system; });
    };
}
