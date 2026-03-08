{ ... }:

{
  name = "lanzaboote-pcrlock";

  nodes.machine =
    { ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest.persistentRoot = true;

      virtualisation.tpm.enable = true;

      # systemd initrd enables boot.initrd.systemd.tpm2.enable by default,
      # which provides pcrphase-initrd, pcrextend, and tpm2-tss store paths.
      boot.initrd.systemd.enable = true;

      systemd.pcrlock.enable = true;
    };

  testScript =
    { nodes, ... }:
    let
      systemd = nodes.machine.systemd.package;
    in
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      import json

      machine.start()

      pcrlock_lock_services = [
        "systemd-pcrlock-firmware-code.service",
        "systemd-pcrlock-firmware-config.service",
        "systemd-pcrlock-secureboot-policy.service",
        "systemd-pcrlock-secureboot-authority.service",
        "systemd-pcrlock-machine-id.service",
        "systemd-pcrlock-file-system.service",
      ]

      with subtest("All pcrlock lock services succeeded"):
        for svc in pcrlock_lock_services:
          machine.wait_for_unit(svc)
          print(f"{svc}: OK")

      with subtest("Lock files were generated"):
        lock_files = machine.succeed("ls /var/lib/pcrlock.d/")
        print(lock_files)
        assert lock_files.strip() != "", "No generated pcrlock component files in /var/lib/pcrlock.d/"

      with subtest("make-policy service succeeded"):
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")

      with subtest("NV index was created in TPM"):
        # list-components proves systemd-pcrlock can talk to the TPM and read its state
        components = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock list-components --json=short")
        comp_data = json.loads(components)
        print(json.dumps(comp_data, indent=2)[:500])
        assert isinstance(comp_data, (dict, list)), f"Expected JSON, got {type(comp_data)}"
        assert len(comp_data) > 0, "list-components returned empty data"

      with subtest("pcrlock policy file contains valid NV index reference"):
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")
        policy_raw = machine.succeed("cat /var/lib/systemd/pcrlock.json")
        policy = json.loads(policy_raw)
        print(json.dumps(policy, indent=2)[:500])
        assert isinstance(policy, dict), f"Expected JSON object, got {type(policy)}"
        assert len(policy) > 0, f"Policy JSON is empty: {list(policy.keys())}"

      with subtest("pcrlock predictions cover expected PCRs"):
        predict_raw = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock predict --json=short")
        predictions = json.loads(predict_raw)
        print(json.dumps(predictions, indent=2)[:1000])

        def collect_pcr_indices(preds):
          indices = set()
          entries = []
          if isinstance(preds, dict):
            for bank_entries in preds.values():
              entries.extend(bank_entries)
          elif isinstance(preds, list):
            entries = preds
          for entry in entries:
            if "pcr" in entry:
              indices.add(entry["pcr"])
          return indices

        all_pcrs = collect_pcr_indices(predictions)
        print(f"Predicted PCRs = {sorted(all_pcrs)}")

        # PCRs 13 (sysexts) and 14 (shim) may be dropped by
        # event_log_reduce_to_safe_pcrs in QEMU (no shim, no sysexts).
        expected_pcrs = {0, 1, 2, 3, 4, 7, 15}
        missing = expected_pcrs - all_pcrs
        assert len(missing) == 0, (
          f"Expected PCRs {sorted(expected_pcrs)} in predictions, "
          f"but missing {sorted(missing)}. Got: {sorted(all_pcrs)}"
        )

        assert 11 not in all_pcrs, (
          "PCR 11 found in predictions — expected auto-drop for thin stubs. "
          f"All predicted PCRs: {sorted(all_pcrs)}"
        )

      with subtest("pcrlock policy survives reboot"):
        machine.reboot()
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("pcrlock predictions still valid after reboot"):
        predict_raw = machine.succeed("${systemd}/lib/systemd/systemd-pcrlock predict --json=short")
        predictions = json.loads(predict_raw)
        assert isinstance(predictions, (dict, list)), "Predictions output is not valid JSON after reboot"
        assert len(predictions) > 0, "Predictions are empty after reboot"
        print(json.dumps(predictions, indent=2)[:500])
    '';
}
