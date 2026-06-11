{ ... }:

{
  name = "lanzaboote-pcrlock-rollforward";

  nodes.machine =
    { config, lib, ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest.persistentRoot = true;

      virtualisation.tpm.enable = true;

      # systemd initrd enables boot.initrd.systemd.tpm2.enable by default,
      # which provides pcrphase-initrd, pcrextend, and tpm2-tss store paths.
      boot.initrd.systemd.enable = true;

      systemd.pcrlock.enable = true;

      system.extraDependencies = [ config.boot.loader.external.installHook ];

      # Acts as "generation 2": different kernel params produce a distinct UKI
      # (different .cmdline PE section) and therefore a different PE hash on
      # the ESP, exercising the lock-pe multi-hash path.
      specialisation.gen2.configuration = {
        boot.kernelParams = lib.mkForce [ "quiet" "loglevel=3" ];
      };
    };

  testScript =
    { nodes, ... }:
    let
      systemd = nodes.machine.systemd.package;
      installHook = nodes.machine.boot.loader.external.installHook;
      policyService = "systemd-pcrlock-make-policy.service";
    in
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + (import ./common/pcrlock-helper.nix)
    + ''
      machine.start()

      with subtest("All pcrlock lock services succeeded on gen1 boot"):
        for svc in [
          "systemd-pcrlock-firmware-code.service",
          "systemd-pcrlock-firmware-config.service",
          "systemd-pcrlock-secureboot-policy.service",
          "systemd-pcrlock-secureboot-authority.service",
          "systemd-pcrlock-machine-id.service",
          "systemd-pcrlock-file-system.service",
        ]:
          machine.wait_for_unit(svc)

      with subtest("make-policy succeeded on gen1 boot"):
        machine.wait_for_unit("${policyService}")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("Thin-stub pcrlock components are preseeded for all installed variants"):
        machine.succeed("test -d /var/lib/pcrlock.d/640-boot-loader.pcrlock.d")
        machine.succeed("test -d /var/lib/pcrlock.d/650-boot-entry.pcrlock.d")
        pcrlock_dir = "/var/lib/pcrlock.d/650-boot-entry.pcrlock.d"
        count_raw = machine.succeed(
          f"ls {pcrlock_dir}/*.pcrlock 2>/dev/null | wc -l"
        ).strip()
        count = int(count_raw)
        assert count >= 2, (
          f"Expected at least 2 per-hash .pcrlock variant files (gen1 + gen2 stub), "
          f"got {count}"
        )

      with subtest("pcrlock predictions valid on gen1 boot"):
        predict_raw = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock predict --json=short")
        predictions = json.loads(predict_raw)
        assert len(predictions) > 0, "Empty predictions on gen1 boot"
        assert 11 in collect_pcr_indices(predictions), "PCR 11 missing from gen1 predictions"

      with subtest("Install hook keeps thin-stub policy refreshable on gen1"):
        machine.succeed("${installHook}")
        machine.succeed("${systemd}/lib/systemd/systemd-pcrlock make-policy --recovery-pin=no --location=770")

      with subtest("Switch default boot entry to gen2 specialisation"):
        machine.succeed(
          "bootctl set-default nixos-generation-1-specialisation-gen2-\\*.efi"
        )
        machine.succeed("sync")

      machine.reboot()

      with subtest("system reaches multi-user target after reboot into gen2"):
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("${policyService}")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("pcrlock predictions still valid after reboot into gen2"):
        predict_raw = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock predict --json=short")
        predictions = json.loads(predict_raw)
        assert isinstance(predictions, (dict, list)), (
          "Predictions output is not valid JSON after reboot into gen2"
        )
        assert len(predictions) > 0, "Empty predictions after reboot into gen2"
        assert 11 in collect_pcr_indices(predictions), (
          f"PCR 11 missing after reboot into gen2: {sorted(collect_pcr_indices(predictions))}"
        )

      with subtest("Running generation is the gen2 specialisation"):
        # The specialisation forces loglevel=3 in kernel params; its presence
        # in /proc/cmdline confirms we booted the specialisation, not gen1.
        cmdline = machine.succeed("cat /proc/cmdline")
        assert "loglevel=3" in cmdline, (
          f"Expected gen2 specialisation kernel params in /proc/cmdline, got: {cmdline}"
        )
    '';
}
