{
  name = "lanzaboote-export-efivars-tpm";

  nodes.machine = {
    imports = [ ./common/lanzaboote.nix ];

    virtualisation.tpm.enable = true;
  };

  testScript =
    { nodes, ... }:
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + (import ./common/efivariables-helper.nix)
    + ''
      machine.start()
      machine.wait_for_unit("default.target")

      # TODO: the other variables are not yet supported.
      expected_variables = [
        "StubPcrKernelImage"
      ]

      # Debug all systemd loader specification GUID EFI variables loaded by the current environment.
      print(machine.succeed(f"ls /sys/firmware/efi/efivars/*-{SD_LOADER_GUID}"))
      with subtest("Check if supported variables are exported"):
          for expected_var in expected_variables:
            machine.succeed(f"test -e /sys/firmware/efi/efivars/{expected_var}-{SD_LOADER_GUID}")

      # "Static" parts of the UKI is measured in PCR11
      assert_variable_string("StubPcrKernelImage", "11")

      with subtest("bootctl reports measured-boot capabilities"):
          bootctl_status = machine.succeed("bootctl status")
          print(bootctl_status)
          assert "Measures kernel+command line+sysexts" in bootctl_status
          assert "Picks up system extension images from boot partition" in bootctl_status
    '';
}
