{ lib, pkgs, ... }:

let

  inherit (pkgs.stdenv.hostPlatform) efiArch;
  efiArchUppercased = lib.toUpper efiArch;

  # A minimal dummy confext image (just needs to be a file with the right suffix).
  dummyConfext = pkgs.runCommand "dummy.confext.raw" { } ''
    dd if=/dev/zero of=$out bs=1024 count=4
  '';

in

{
  name = "lanzaboote-confext";

  nodes.machine = {
    imports = [ ./common/lanzaboote.nix ];

    virtualisation.tpm.enable = true;

    environment.etc."lanzaboote-tests/dummy.confext.raw".source = dummyConfext;

    # Log the stub-delivered companion files from inside the initrd, where
    # /.extra/ is visible, so the test can assert on the delivery.
    boot.initrd.systemd.enable = true;
    boot.initrd.systemd.services.lanzaboote-test-list-extra = {
      wantedBy = [ "initrd.target" ];
      before = [ "initrd.target" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig.Type = "oneshot";
      script = ''
        find /.extra -type f > /dev/kmsg 2>&1 || echo "lanzaboote-test: no /.extra" > /dev/kmsg
      '';
    };
  };

  testScript =
    { nodes, ... }:
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + (import ./common/efivariables-helper.nix)
    + ''
      import struct

      machine.start()

      # Copy the stub as the default boot entry so we boot into it directly.
      machine.succeed("cp /boot/EFI/Linux/nixos-generation-1-*.efi /boot/EFI/BOOT/BOOT${efiArchUppercased}.EFI")
      machine.succeed("cp /boot/EFI/Linux/nixos-generation-1-*.efi /boot/EFI/systemd/systemd-boot${efiArch}.efi")

      # Place a confext.raw in the preferred drop-in directory.
      machine.succeed("mkdir -p '/boot/EFI/BOOT/BOOT${efiArchUppercased}.EFI.extra.d'")
      machine.succeed("cp /etc/lanzaboote-tests/dummy.confext.raw '/boot/EFI/BOOT/BOOT${efiArchUppercased}.EFI.extra.d/dummy.confext.raw'")

      # Also place a regular sysext to verify it is not confused with confexts.
      machine.succeed("cp /etc/lanzaboote-tests/dummy.confext.raw '/boot/EFI/BOOT/BOOT${efiArchUppercased}.EFI.extra.d/dummy.raw'")

      machine.succeed("sync")
      machine.crash()
      machine.start()

      with subtest("StubFeatures includes PickUpConfExts (bit 8)"):
          features = struct.unpack('<Q', read_raw_variable("StubFeatures"))[0]
          assert features & (1 << 8), f"PickUpConfExts bit not set in StubFeatures: {features:#x}"

      with subtest("Companion files are delivered into the initrd"):
          journal = machine.succeed("journalctl -b --no-pager | grep -F '/.extra/' || true")
          print(f"stub-delivered files: {journal}")
          assert "/.extra/confext/dummy.confext.raw" in journal, \
              f"confext not delivered to the initrd: {journal}"

      with subtest("Confext measurement extends PCR 12"):
          # StubPcrKernelParameters is set when anything is measured into PCR 12,
          # which includes configuration extensions.
          assert_variable_string("StubPcrKernelParameters", "12")
          assert_variable_string("StubPcrInitRDConfExts", "12")
    '';
}
