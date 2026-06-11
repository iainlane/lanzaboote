{ pkgs, ... }:

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
        gen1_pcrs = collect_pcr_indices(predictions)
        assert {0, 1, 2, 3, 4, 7} <= gen1_pcrs, f"firmware PCRs missing from gen1 predictions: {sorted(gen1_pcrs)}"
        policy_pcrs = set(json.loads(machine.succeed(
          """${pkgs.jq}/bin/jq -c '[.pcrValues[].pcr] | unique' /var/lib/systemd/pcrlock.json"""
        )))
        assert policy_pcrs == {0, 1, 2, 3, 4, 7, 13, 15}, (
          f"policy must cover exactly the firmware PCRs, leaving PCR 11 to "
          f"the signed policy shard: {sorted(policy_pcrs)}"
        )

      with subtest("Install hook keeps thin-stub policy refreshable on gen1"):
        machine.succeed("${installHook}")

      # Validate the prediction parity of the historical drop-in directory
      # by giving the running generation a sysext through it and rebooting:
      # the policy can only keep covering PCR 13 if the predicted archive
      # matches what the stub measures.
      with subtest("Legacy .extra sysexts are predicted for the running generation"):
        gen1_stub = machine.succeed(
          "ls /boot/EFI/Linux/nixos-generation-1-*.efi | grep -v specialisation | head -n1"
        ).strip()
        machine.succeed(f"mkdir -p {gen1_stub}.extra")
        machine.succeed(f"dd if=/dev/urandom of={gen1_stub}.extra/local.sysext.raw bs=1024 count=4")
        machine.succeed("${installHook}")
        machine.succeed("sync")

      machine.reboot()

      with subtest("Policy still covers PCR 13 after rebooting with the legacy sysext"):
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("${policyService}")
        policy_pcrs = set(json.loads(machine.succeed(
          """${pkgs.jq}/bin/jq -c '[.pcrValues[].pcr] | unique' /var/lib/systemd/pcrlock.json"""
        )))
        assert 13 in policy_pcrs, (
          f"PCR 13 dropped: legacy drop-in prediction does not match the stub: {sorted(policy_pcrs)}"
        )

      # The preferred drop-in directory form, and the global extensions
      # directory, are validated across the switch to gen2.
      with subtest("System extensions are predicted before the switch"):
        machine.succeed("mkdir -p /boot/loader/extensions")
        machine.succeed("dd if=/dev/urandom of=/boot/loader/extensions/global.raw bs=1024 count=4")
        stub = machine.succeed(
          "ls /boot/EFI/Linux/nixos-generation-1-specialisation-gen2-*.efi | head -n1"
        ).strip()
        dropin = stub.removesuffix(".efi") + ".efi.extra.d"
        machine.succeed(f"mkdir -p {dropin}")
        machine.succeed(f"dd if=/dev/urandom of={dropin}/local.sysext.raw bs=1024 count=4")
        machine.succeed("${installHook}")
        machine.succeed("ls /var/lib/pcrlock.d/655-global-sysext.pcrlock.d/*.pcrlock")

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
        gen2_pcrs = collect_pcr_indices(predictions)
        assert {0, 1, 2, 3, 4, 7} <= gen2_pcrs, (
          f"firmware PCRs missing after reboot into gen2: {sorted(gen2_pcrs)}"
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
