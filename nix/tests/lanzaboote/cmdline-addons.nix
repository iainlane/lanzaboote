{ lib, pkgs, ... }:

let

  inherit (pkgs.stdenv.hostPlatform) efiArch;
  efiArchUppercased = lib.toUpper efiArch;

  signedAddon = pkgs.runCommand "signed-test.addon.efi"
    {
      nativeBuildInputs = [ pkgs.systemdUkify pkgs.sbsigntool ];
    } ''
    echo -n "lanzaboote.test_addon=signed" > cmdline.txt
    ukify build \
      --cmdline=@cmdline.txt \
      --output=unsigned.addon.efi
    sbsign \
      --key ${../fixtures/uefi-keys}/keys/db/db.key \
      --cert ${../fixtures/uefi-keys}/keys/db/db.pem \
      --output=$out \
      unsigned.addon.efi
  '';

  unsignedAddon = pkgs.runCommand "unsigned-test.addon.efi"
    {
      nativeBuildInputs = [ pkgs.systemdUkify ];
    } ''
    echo -n "lanzaboote.test_addon=unsigned" > cmdline.txt
    ukify build \
      --cmdline=@cmdline.txt \
      --output=$out
  '';

in

{
  name = "lanzaboote-cmdline-addons";

  nodes.machine = {
    imports = [ ./common/lanzaboote.nix ];

    virtualisation.tpm.enable = true;

    environment.etc = {
      "lanzaboote-tests/signed.addon.efi".source = signedAddon;
      "lanzaboote-tests/unsigned.addon.efi".source = unsignedAddon;
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

      # Place signed and unsigned addons in the global addons directory.
      machine.succeed("mkdir -p /boot/loader/addons")
      machine.succeed("cp /etc/lanzaboote-tests/signed.addon.efi /boot/loader/addons/SIGNED.ADDON.EFI")
      machine.succeed("cp /etc/lanzaboote-tests/unsigned.addon.efi /boot/loader/addons/UNSIGNED.ADDON.EFI")

      machine.succeed("sync")
      machine.crash()
      machine.start()

      with subtest("StubFeatures includes CmdlineAddons (bit 5)"):
          features = struct.unpack('<Q', read_raw_variable("StubFeatures"))[0]
          assert features & (1 << 5), f"CmdlineAddons bit not set in StubFeatures: {features:#x}"

      with subtest("Addon cmdline was measured into PCR 12"):
          assert_variable_string("StubPcrKernelParameters", "12")

      with subtest("Addon cmdline is appended to kernel command line"):
          cmdline = machine.succeed("cat /proc/cmdline")
          print(f"Kernel command line: {cmdline}")
          assert "lanzaboote.test_addon=signed" in cmdline, \
              f"Signed addon parameter not found in /proc/cmdline: {cmdline}"
          assert "lanzaboote.test_addon=unsigned" not in cmdline, \
              f"Unsigned addon parameter unexpectedly present in /proc/cmdline: {cmdline}"
    '';
}
