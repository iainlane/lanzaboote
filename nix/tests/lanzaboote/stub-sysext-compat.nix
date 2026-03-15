{ pkgs, ... }:

let
  # A minimal but valid system extension: a squashfs with the release
  # metadata systemd-sysext requires, scoped to the initrd, plus a marker
  # file whose appearance under /usr proves the merge happened.
  validSysext = pkgs.runCommand "test-sysext.raw" { nativeBuildInputs = [ pkgs.squashfsTools ]; } ''
    mkdir -p tree/usr/lib/extension-release.d
    printf 'ID=_any\nSYSEXT_SCOPE=initrd\n' > tree/usr/lib/extension-release.d/extension-release.test-sysext
    touch tree/usr/lanzaboote-sysext-marker
    mksquashfs tree $out -all-root -noappend -quiet
  '';
in
{
  name = "lanzaboote-stub-sysext-compat";

  nodes.machine =
    { config, ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      virtualisation.tpm.enable = true;

      environment.etc."lanzaboote-tests/test-sysext.raw".source = validSysext;

      # Merge stub-delivered system extensions inside the initrd, and log
      # the result to the kernel ring buffer where the test can assert on
      # it after the boot has completed.
      boot.initrd.systemd.enable = true;
      boot.initrd.availableKernelModules = [
        "squashfs"
        "loop"
        "overlay"
      ];
      boot.initrd.systemd.additionalUpstreamUnits = [ "systemd-sysext-initrd.service" ];
      boot.initrd.systemd.services.systemd-sysext-initrd = {
        wantedBy = [ "initrd.target" ];
        # The default image policy in the initrd requires verity-protected
        # images. Verifying images is systemd's business; this test only
        # proves the stub's delivery feeds systemd-sysext, so accept the
        # unprotected test image.
        serviceConfig.ExecStart = [
          ""
          "systemd-sysext refresh --image-policy=root=unprotected+absent:usr=unprotected+absent"
        ];
      };
      boot.initrd.systemd.storePaths = [ "${config.boot.initrd.systemd.package}/bin/systemd-sysext" ];
      boot.initrd.systemd.services.lanzaboote-test-sysext-probe = {
        wantedBy = [ "initrd.target" ];
        after = [ "systemd-sysext-initrd.service" ];
        unitConfig.DefaultDependencies = false;
        serviceConfig.Type = "oneshot";
        script = ''
          if [ -e /usr/lanzaboote-sysext-marker ]; then
            echo "lanzaboote-test: sysext merged" > /dev/kmsg
          else
            echo "lanzaboote-test: sysext NOT merged" > /dev/kmsg
          fi
        '';
      };
    };

  testScript =
    { nodes, ... }:
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + (import ./common/efivariables-helper.nix)
    + ''
      machine.start()
      machine.wait_for_unit("default.target")

      with subtest("bootctl reports systemd-stub compatible sysext capabilities"):
        bootctl_status = machine.succeed("bootctl status")
        print(bootctl_status)
        assert "Picks up system extension images from boot partition" in bootctl_status
        assert "Measures kernel+command line+sysexts" in bootctl_status

      with subtest("Image-local .efi.extra.d sysexts are discovered and measured"):
        uki_path = machine.succeed("echo /boot/EFI/Linux/nixos-generation-1-*.efi").strip()
        machine.succeed("rm -rf /boot/loader/extensions")
        machine.succeed(f"mkdir -p {uki_path}.extra.d")
        machine.succeed(f"printf local > {uki_path}.extra.d/local.sysext.raw")
        machine.reboot()
        machine.wait_for_unit("default.target")
        assert_variable_string("StubPcrInitRDSysExts", "13")

      with subtest("Legacy .extra sysexts remain supported as a fallback"):
        uki_path = machine.succeed("echo /boot/EFI/Linux/nixos-generation-1-*.efi").strip()
        machine.succeed(f"rm -rf {uki_path}.extra.d")
        machine.succeed("rm -rf /boot/loader/extensions")
        machine.succeed(f"mkdir -p {uki_path}.extra")
        machine.succeed(f"printf legacy > {uki_path}.extra/legacy.sysext.raw")
        machine.reboot()
        machine.wait_for_unit("default.target")
        assert_variable_string("StubPcrInitRDSysExts", "13")

      with subtest("A valid sysext is merged inside the initrd"):
        uki_path = machine.succeed("echo /boot/EFI/Linux/nixos-generation-1-*.efi").strip()
        machine.succeed(f"rm -rf {uki_path}.extra")
        machine.succeed(f"mkdir -p {uki_path}.extra.d")
        machine.succeed(f"cp /etc/lanzaboote-tests/test-sysext.raw {uki_path}.extra.d/test-sysext.raw")
        machine.reboot()
        machine.wait_for_unit("default.target")
        journal = machine.succeed("journalctl -b --no-pager | grep 'lanzaboote-test: sysext' || true")
        print(journal)
        assert "lanzaboote-test: sysext merged" in journal, f"sysext was not merged in the initrd: {journal}"

      with subtest("Global /loader/extensions sysexts are discovered and measured"):
        uki_path = machine.succeed("echo /boot/EFI/Linux/nixos-generation-1-*.efi").strip()
        machine.succeed(f"rm -rf {uki_path}.extra.d")
        machine.succeed(f"rm -rf {uki_path}.extra")
        machine.succeed("rm -rf /boot/loader/extensions")
        machine.succeed("mkdir -p /boot/loader/extensions")
        machine.succeed("printf global > /boot/loader/extensions/global.sysext.raw")
        machine.reboot()
        machine.wait_for_unit("default.target")
        assert_variable_string("StubPcrInitRDSysExts", "13")
    '';
}
