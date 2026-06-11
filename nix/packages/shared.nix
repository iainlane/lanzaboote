{
  lib,
  buildRustApp,
}:

buildRustApp {
  pname = "lanzaboote-shared";
  src = lib.sourceFilesBySuffices ../../rust [
    ".rs"
    ".toml"
    ".lock"
  ];
  args = {
    cargoToml = ../../rust/Cargo.toml;
    cargoLock = ../../rust/Cargo.lock;
  };
  packageArgs = {
    # The workspace only contains a library crate; there is nothing to
    # install, but building it runs the unit tests.
    installPhaseCommand = "mkdir -p $out";
  };
}
