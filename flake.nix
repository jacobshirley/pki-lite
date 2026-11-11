{
  description = "pki-lite development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # The repo pins its package manager (`packageManager` in package.json) and pnpm >= 11
      # always switches to that exact version by downloading a generic-Linux binary, which
      # NixOS cannot run. nixpkgs' pnpm is also older than the pin. So provide the pinned
      # pnpm itself: nix/pnpm.json holds its version and hashes, refreshed by
      # scripts/update-pnpm-nix.sh.
      pinned = builtins.fromJSON (builtins.readFile ./package.json);
      pnpmLock = builtins.fromJSON (builtins.readFile ./nix/pnpm.json);
      pnpmVersion = nixpkgs.lib.removePrefix "pnpm@" pinned.packageManager;

      mkPnpm = pkgs:
        let
          system = pkgs.stdenv.hostPlatform.system;
          entry = pnpmLock.systems.${system};
        in
        assert nixpkgs.lib.assertMsg (pnpmLock.version == pnpmVersion)
          "nix/pnpm.json is for pnpm ${pnpmLock.version} but package.json pins ${pnpmVersion}: run scripts/update-pnpm-nix.sh";
        pkgs.stdenv.mkDerivation {
          pname = "pnpm";
          version = pnpmVersion;
          src = pkgs.fetchurl {
            url = "https://registry.npmjs.org/@pnpm/exe.${entry.platform}/-/exe.${entry.platform}-${pnpmVersion}.tgz";
            hash = entry.hash;
          };
          nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.autoPatchelfHook ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.stdenv.cc.cc.lib ];
          # A single-executable app: stripping would remove its embedded payload.
          dontStrip = true;
          installPhase = "install -Dm755 pnpm $out/bin/pnpm";
        };
    in
    {
      packages = forAllSystems (pkgs: { pnpm = mkPnpm pkgs; });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_24 # CI uses Node 24
            (mkPnpm pkgs)
            pkgs.openssl # the OpenSSL compatibility tests fall back to this when docker is absent
            pkgs.git
          ];

          shellHook = nixpkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            # Playwright's own downloaded browsers cannot run on NixOS, so point the browser
            # tests at the Chromium that nixpkgs ships (see vitest.config.ts).
            export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
            for chrome in ${pkgs.playwright-driver.browsers}/chromium-*/chrome-linux*/chrome; do
              export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chrome"
            done
          '';
        };
      });
    };
}
