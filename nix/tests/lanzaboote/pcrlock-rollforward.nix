{ ... }:

{
  name = "lanzaboote-pcrlock-rollforward";

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest.persistentRoot = true;

      virtualisation.tpm.enable = true;

      # systemd initrd enables boot.initrd.systemd.tpm2.enable by default,
      # which provides pcrphase-initrd, pcrextend, and tpm2-tss store paths.
      boot.initrd.systemd.enable = true;

      systemd.pcrlock.enable = true;

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
    in
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      import json

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
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("pcrlock predictions valid on gen1 boot"):
        predict_raw = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock predict --json=short")
        predictions = json.loads(predict_raw)
        assert len(predictions) > 0, "Empty predictions on gen1 boot"

      # Capture the policy before the rollforward so we can confirm it changes
      # after the install hook re-runs make-policy for the new stub.
      policy_before = machine.succeed("cat /var/lib/systemd/pcrlock.json")

      with subtest("Install hook re-runs lock-pe and make-policy for gen2"):
        machine.succeed("${installHook}")

      with subtest("Lock-pe variant directory contains multiple .pcrlock files"):
        pcrlock_dir = "/var/lib/pcrlock.d/760-boot-entry.pcrlock.d"
        count_raw = machine.succeed(
          f"ls {pcrlock_dir}/*.pcrlock 2>/dev/null | wc -l"
        ).strip()
        count = int(count_raw)
        assert count >= 2, (
          f"Expected at least 2 per-hash .pcrlock variant files (gen1 + gen2 stub), "
          f"got {count}"
        )

      with subtest("make-policy updated the policy after gen2 install"):
        policy_after = machine.succeed("cat /var/lib/systemd/pcrlock.json")
        assert policy_before != policy_after, (
          "pcrlock.json did not change after rollforward — "
          "make-policy may not have updated the NV index"
        )

      with subtest("Switch default boot entry to gen2 specialisation"):
        machine.succeed(
          "bootctl set-default nixos-generation-1-specialisation-gen2-\\*.efi"
        )
        machine.succeed("sync")

      machine.reboot()

      with subtest("make-policy succeeded after reboot into gen2"):
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("pcrlock predictions still valid after reboot into gen2"):
        predict_raw = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock predict --json=short")
        predictions = json.loads(predict_raw)
        assert isinstance(predictions, (dict, list)), (
          "Predictions output is not valid JSON after reboot into gen2"
        )
        assert len(predictions) > 0, "Empty predictions after reboot into gen2"

      with subtest("Running generation is the gen2 specialisation"):
        # The specialisation forces loglevel=3 in kernel params; its presence
        # in /proc/cmdline confirms we booted the specialisation, not gen1.
        cmdline = machine.succeed("cat /proc/cmdline")
        assert "loglevel=3" in cmdline, (
          f"Expected gen2 specialisation kernel params in /proc/cmdline, got: {cmdline}"
        )
    '';
}
